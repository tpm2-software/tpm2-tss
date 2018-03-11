#include <stdbool.h>

#define LOGMODULE test
#include "util/log.h"
#include "test-esapi.h"
#include "test-options.h"
#include "context-util.h"
#include "tss2_esys.h"
#include "esys_types.h"
#include "esys_iutil.h"
#include "tss2_tcti.h"
#include "tss2-tcti/tcti.h"

/** Define a proxy tcti that returns yielded on every second invocation
 * thus the corresponding handling code in ESAPI can be tested.
 * The first invocation will be Tss2_Sys_StartUp.
 */

#define TCTI_PROXY_MAGIC 0x5250584f0a000000ULL /* 'PROXY\0\0\0' */
#define TCTI_PROXY_VERSION 0x1

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
              TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
    TSS2_TCTI_CONTEXT *tctiInner;
    uint8_t count;
} TSS2_TCTI_CONTEXT_PROXY;

static TSS2_TCTI_CONTEXT_PROXY*
tcti_proxy_cast (TSS2_TCTI_CONTEXT *ctx)
{
    TSS2_TCTI_CONTEXT_PROXY *ctxi = (TSS2_TCTI_CONTEXT_PROXY*)ctx;
    if (ctxi == NULL || ctxi->magic != TCTI_PROXY_MAGIC) {
        LOG_ERROR("Bad tcti passed.");
        return NULL;
    }
    return ctxi;
}

static TSS2_RC
tcti_proxy_transmit(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);
    if (tcti_proxy->count == 2) {
        tcti_proxy->count = 1;
        return TSS2_RC_SUCCESS;
    }
    tcti_proxy->count++;

    rval = Tss2_Tcti_Transmit(tcti_proxy->tctiInner, command_size,
        command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI Transmit");
        return rval;
    }

    return rval;
}

uint8_t yielded_response[] = {
    0x00, 0x00,             /* TPM_ST_NO_SESSION */
    0x00, 0x00, 0x00, 0x0A, /* Response Size 10 */
    0x00, 0x00, 0x09, 0x08  /* TPM_RC_YIELDED */
};

static TSS2_RC
tcti_proxy_receive(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->count == 2) {
        *response_size = sizeof(yielded_response);
        if (response_buffer != NULL)
            memcpy(response_buffer, &yielded_response[0], sizeof(yielded_response));

        return TSS2_RC_SUCCESS;
    }

    rval = Tss2_Tcti_Receive(tcti_proxy->tctiInner, response_size,
                             response_buffer, timeout);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI Transmit");
        return rval;
    }

    return rval;
}

static void
tcti_proxy_finalize(
    TSS2_TCTI_CONTEXT *tctiContext)
{
    memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_PROXY));
}

static TSS2_RC
tcti_proxy_initialize(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    TSS2_TCTI_CONTEXT *tctiInner)
{
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy =
        (TSS2_TCTI_CONTEXT_PROXY*) tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_proxy);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_proxy, 0, sizeof(*tcti_proxy));
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_PROXY_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_proxy_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_proxy_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_proxy_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = NULL;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = NULL;
    tcti_proxy->tctiInner = tctiInner;
    tcti_proxy->count = 0;

    return TSS2_RC_SUCCESS;
}

/** Override the gcrypt random functions in order to not screw over valgrind. */
TSS2_RC iesys_cryptogcry_random2b(TPM2B_NONCE *nonce, size_t num_bytes)
{
    nonce->size = num_bytes;
    for (int i = 0; i < num_bytes; i++)
        nonce->buffer[i] = i % 256;
    return 0;
}

/**
 * This program is a template for integration tests (ones that use the TCTI
 * and the ESAPI contexts / API directly). It does nothing more than parsing
 * command line options that allow the caller (likely a script) to specify
 * which TCTI to use for the test.
 */
int
main(int argc, char *argv[])
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_context = calloc(1,
        sizeof(TSS2_TCTI_CONTEXT_PROXY));
    TSS2_TCTI_CONTEXT *tcti_inner;
    ESYS_CONTEXT *esys_context;
    TSS2_ABI_VERSION abiVersion =
        { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL,
TSS_SAPI_FIRST_VERSION };

    int ret;
    test_opts_t opts = {
        .tcti_type = TCTI_DEFAULT,
        .device_file = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port = PORT_DEFAULT,
    };

    get_test_opts_from_env(&opts);
    if (sanity_check_test_opts(&opts) != 0) {
        LOG_ERROR("TPM Startup FAILED! Error in sanity check");
        exit(1);
    }
    tcti_inner = tcti_init_from_opts(&opts);
    if (tcti_inner == NULL) {
        LOG_ERROR("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
    size_t tcti_size = sizeof(TSS2_TCTI_CONTEXT_PROXY);
    rc = tcti_proxy_initialize(tcti_context, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("tcti initialization FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    rc = Esys_Initialize(&esys_context, tcti_context, &abiVersion);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        LOG_ERROR("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    rc = Esys_SetTimeout(esys_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        LOG_ERROR("Esys_SetTimeout FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    rc = Tss2_Sys_Startup(esys_context->sys, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        LOG_ERROR("TPM Startup FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    ret = test_invoke_esapi(esys_context);

    Esys_Finalize(&esys_context);
    tcti_teardown(tcti_context);
    return ret;
}
