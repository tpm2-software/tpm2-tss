#include <stdbool.h>

#define LOGMODULE test
#include "log/log.h"
#include "test-esapi.h"
#include "test-options.h"
#include "context-util.h"
#include <esapi/tss2_esys.h>
#include <esys_types.h>
#include "esys_iutil.h"


/** Override the gcrypt random functions in order to not screw over valgrind. */
TSS2_RC iesys_cryptogcry_random2b(TPM2B_NONCE *nonce, size_t num_bytes) {
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
    TSS2_TCTI_CONTEXT *tcti_context;
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
    tcti_context = tcti_init_from_opts(&opts);
    if (tcti_context == NULL) {
        LOG_ERROR("TPM Startup FAILED! Error tcti init");
        exit(1);
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
