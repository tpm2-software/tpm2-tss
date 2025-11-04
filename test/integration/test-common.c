/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>         // for PRIx32, uint8_t, int32_t, uint32_t, uin...
#include <stdbool.h>          // for bool
#include <stdio.h>            // for NULL, size_t
#include <stdlib.h>           // for free, malloc, EXIT_SUCCESS, getenv
#include <string.h>           // for memset, memcmp, memcpy

#include "tss2_common.h"      // for TSS2_RC_SUCCESS, TSS2_RC, UINT32, TSS2_...
#include "tss2_mu.h"          // for Tss2_MU_TPMS_CAPABILITY_DATA_Marshal
#include "tss2_tctildr.h"     // for Tss2_TctiLdr_Finalize, Tss2_TctiLdr_Ini...
#include "tss2_tpm2_types.h"  // for TPMS_CAPABILITY_DATA, TPM2_CAP_HANDLES
#ifdef TEST_ESYS
#include "tss2_esys.h"        // for Esys_Finalize, Esys_GetSysContext, Esys...
#endif
#define LOGMODULE test
#include "test-common.h"
#include "util/log.h"         // for LOG_ERROR, LOG_DEBUG, LOGBLOB_ERROR


#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))


struct {
    TPM2_CAP cap;
    UINT32 prop;
    UINT32 count;
} capabilities_to_dump[] = {
    {TPM2_CAP_PCRS, 0, 10},
    {TPM2_CAP_HANDLES, TPM2_HR_PCR, TPM2_MAX_CAP_HANDLES},
    {TPM2_CAP_HANDLES, TPM2_HR_HMAC_SESSION, TPM2_MAX_CAP_HANDLES},
    {TPM2_CAP_HANDLES, TPM2_HR_POLICY_SESSION, TPM2_MAX_CAP_HANDLES},
    {TPM2_CAP_HANDLES, TPM2_HR_TRANSIENT, TPM2_MAX_CAP_HANDLES},
    {TPM2_CAP_HANDLES, TPM2_HR_PERSISTENT, TPM2_MAX_CAP_HANDLES},
    {TPM2_CAP_HANDLES, TPM2_HR_NV_INDEX, TPM2_MAX_CAP_HANDLES},
};

struct tpm_state {
    TPMS_CAPABILITY_DATA capabilities[7];
};

/** Define a proxy tcti that returns yielded on every second invocation
 * thus the corresponding handling code in ESYS can be tested.
 * The first invocation will be Tss2_Sys_StartUp.
 */
#ifdef TEST_ESYS

TSS2_RC
(*transmit_hook) (const uint8_t *command_buffer, size_t command_size) = NULL;

#define TCTI_PROXY_MAGIC 0x5250584f0a000000ULL /* 'PROXY\0\0\0' */
#define TCTI_PROXY_VERSION 0x1

enum state {
    forwarding,
    intercepting
};

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
    enum state state;
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

    if (tcti_proxy->state == intercepting) {
        return TSS2_RC_SUCCESS;
    }

    if (transmit_hook != NULL) {
        rval = transmit_hook(command_buffer, command_size);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_ERROR("transmit hook requested error");
            return rval;
        }
    }

    rval = Tss2_Tcti_Transmit(tcti_proxy->tctiInner, command_size,
        command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI Transmit");
        return rval;
    }

    return rval;
}

uint8_t yielded_response[] = {
    0x80, 0x01,             /* TPM_ST_NO_SESSION */
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

    if (tcti_proxy->state == intercepting) {
        *response_size = sizeof(yielded_response);

        if (response_buffer != NULL) {
            memcpy(response_buffer, &yielded_response[0], sizeof(yielded_response));
            tcti_proxy->state = forwarding;
        }
        return TSS2_RC_SUCCESS;
    }

    rval = Tss2_Tcti_Receive(tcti_proxy->tctiInner, response_size,
                             response_buffer, timeout);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI Transmit");
        return rval;
    }

    /* First read with response buffer == NULL is to get the size of the
     * response. The subsequent read needs to be forwarded also */
    if (response_buffer != NULL)
        tcti_proxy->state = intercepting;

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
    TSS2_TCTI_VERSION (tctiContext) = TCTI_PROXY_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_proxy_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_proxy_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_proxy_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = NULL;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = NULL;
    tcti_proxy->tctiInner = tctiInner;
    tcti_proxy->state = forwarding;

    return TSS2_RC_SUCCESS;
}
#endif /* TEST_ESYS */

int
transient_empty(TSS2_SYS_CONTEXT *sys_ctx)
{
    TSS2_RC rc;
    TPMS_CAPABILITY_DATA caps;

    do {
        rc = Tss2_Sys_GetCapability(sys_ctx,
                                    NULL,
                                    TPM2_CAP_HANDLES,
                                    TPM2_HR_TRANSIENT,
                                    ARRAY_SIZE(caps.data.handles.handle),
                                    NULL,
                                    &caps,
                                    NULL);
    } while (rc == TPM2_RC_YIELDED); // TODO also for other cmds?
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("TPM2_GetCapabilities failed: 0x%" PRIx32, rc);
        return EXIT_ERROR;
    }

    if (caps.data.handles.count) {
        LOG_ERROR("TPM holds transient objects");
        for (UINT32 i = 0; i < caps.data.handles.count; i++) {
            LOG_ERROR("Handle 0x%"PRIx32, caps.data.handles.handle[i]);
        }
        return EXIT_ERROR;
    }

    return EXIT_SUCCESS;
}

int
dumpstate(TSS2_SYS_CONTEXT *sys_ctx, tpm_state *state_first, bool compare)
{
    TSS2_RC rc;
    tpm_state state_second;
    tpm_state *states[] = {state_first, &state_second};
    TPMS_CAPABILITY_DATA *capabilities;
    uint8_t buffer[2][sizeof(TPMS_CAPABILITY_DATA)];
    size_t off[2] = {0, 0};

    if (!compare) {
        /* capture and return first state */
        capabilities = state_first->capabilities;
    } else {
        /* capture second state and compare */
        capabilities = state_second.capabilities;
    }
    for (size_t i = 0; i < ARRAY_SIZE(capabilities_to_dump); i++) {
        do {
            rc = Tss2_Sys_GetCapability(sys_ctx,
                                        NULL,
                                        capabilities_to_dump[i].cap,
                                        capabilities_to_dump[i].prop,
                                        capabilities_to_dump[i].count,
                                        NULL,
                                        &capabilities[i],
                                        NULL);
        } while (rc == TPM2_RC_YIELDED); // TODO also for other cmds?
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR("TPM2_GetCapabilities failed: 0x%" PRIx32, rc);
            return EXIT_ERROR;
        }
    }

    if (!compare) {
        return TPM2_RC_SUCCESS;
    }

    for (int i = 0; i < (int) ARRAY_SIZE(capabilities_to_dump); i++) {
        /* marshal both first and second for easy comparison */
        for (int j = 0; j < 2; j++) {
            rc = Tss2_MU_TPMS_CAPABILITY_DATA_Marshal(&states[j]->capabilities[i],
                                                      buffer[j],
                                                      ARRAY_SIZE(buffer[j]),
                                                      &off[j]);
            if (rc != TSS2_RC_SUCCESS) {
                LOG_ERROR("Marshaling failed: 0x%" PRIx32, rc);
                return EXIT_ERROR;
            }
        }

        if (off[0] != off[1] || memcmp(buffer[0], buffer[1], off[0]) != 0) {
            LOG_ERROR("TPM states are not equal for capability 0x%08x, property 0x%08x",
                      capabilities_to_dump[i].cap,
                      capabilities_to_dump[i].prop);
            LOGBLOB_ERROR(buffer[0], off[0], "Before");
            LOGBLOB_ERROR(buffer[1], off[1], "After");

            rc = EXIT_ERROR;
        }
    }

    return rc;
}

int
test_sys_setup(TSS2_TEST_SYS_CONTEXT **test_ctx)
{
    TSS2_RC rc;
    TSS2_ABI_VERSION abi_version = TEST_ABI_VERSION;
    size_t size;
    char *name_conf;

    size = sizeof(TSS2_TEST_SYS_CONTEXT);
    *test_ctx = malloc(size);
    if (test_ctx == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for the test context", size);
        goto fail;
    }

    name_conf = getenv(ENV_TCTI); // TODO arg, then env?
    if (!name_conf) {
        LOG_ERROR("TCTI module not specified. Use environment variable: " ENV_TCTI);
        goto cleanup_test_ctx;
    }

    rc = Tss2_TctiLdr_Initialize(name_conf, &(*test_ctx)->tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error loading TCTI: %s", name_conf);
        goto cleanup_test_ctx;
    }

    size = Tss2_Sys_GetContextSize(0);
    (*test_ctx)->sys_ctx = malloc(size);
    if ((*test_ctx)->sys_ctx == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for the System API context", size);
        goto cleanup_tcti_ctx;
    }
    rc = Tss2_Sys_Initialize((*test_ctx)->sys_ctx, size, (*test_ctx)->tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to initialize System API context: 0x%x", rc);
        goto cleanup_sys_mem;
    }

    rc = Tss2_Sys_Startup((*test_ctx)->sys_ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        LOG_ERROR("TPM2_Startup failed: 0x%" PRIx32, rc);
        goto cleanup_sys_ctx;
    }

    (*test_ctx)->tpm_state = malloc(sizeof(tpm_state));
    if (test_ctx == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for tpm_state.", size);
        goto cleanup_sys_ctx;
    }

    return TPM2_RC_SUCCESS;

    free((*test_ctx)->tpm_state);

cleanup_sys_ctx:
    Tss2_Sys_Finalize((*test_ctx)->sys_ctx);

cleanup_sys_mem:
    free((*test_ctx)->sys_ctx);

cleanup_tcti_ctx:
    Tss2_TctiLdr_Finalize(&(*test_ctx)->tcti_ctx);

cleanup_test_ctx:
    free(*test_ctx);

fail:
    return EXIT_ERROR;
}

int
test_sys_checks_pre(TSS2_TEST_SYS_CONTEXT *test_ctx)
{
    int ret;

    LOG_DEBUG("Running System API pre-test checks: transient handles empty");
    ret = transient_empty(test_ctx->sys_ctx);
    if (ret != EXIT_SUCCESS) {
        LOG_ERROR("TPM contains transient objects.");
        return ret;
    }

    LOG_DEBUG("Running System API pre-test checks: dump capabilities");
    ret = dumpstate(test_ctx->sys_ctx, test_ctx->tpm_state, 0);
    if (ret != EXIT_SUCCESS) {
        LOG_ERROR("Error while dumping TPM state.");
        return ret;
    }

    return EXIT_SUCCESS;
}

int
test_sys_checks_post(TSS2_TEST_SYS_CONTEXT *test_ctx)
{
    int ret;

    LOG_DEBUG("Running System API post-test checks: dump capabilities");
    ret = dumpstate(test_ctx->sys_ctx, test_ctx->tpm_state, 1);
    if (ret != EXIT_SUCCESS) {
        LOG_ERROR("Error while performing TPM state checks.");
        return ret;
    }

    return EXIT_SUCCESS;
}

void
test_sys_teardown(TSS2_TEST_SYS_CONTEXT *test_ctx)
{
    if (test_ctx) {
        free(test_ctx->tpm_state);
        Tss2_Sys_Finalize(test_ctx->sys_ctx);
        free(test_ctx->sys_ctx);
        Tss2_TctiLdr_Finalize(&test_ctx->tcti_ctx);
        free(test_ctx);
    }
}

#ifdef TEST_ESYS
int
test_esys_setup(TSS2_TEST_ESYS_CONTEXT **test_ctx)
{
    TSS2_RC rc;
    TSS2_ABI_VERSION abi_version = TEST_ABI_VERSION;
    size_t size;
    char *name_conf;

    size = sizeof(TSS2_TEST_ESYS_CONTEXT);
    *test_ctx = malloc(size);
    if (test_ctx == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for the test context", size);
        goto fail;
    }

    name_conf = getenv(ENV_TCTI); // TODO arg, then env?
    if (!name_conf) {
        LOG_ERROR("TCTI module not specified. Use environment variable: " ENV_TCTI);
        goto cleanup_test_ctx;
    }

    rc = Tss2_TctiLdr_Initialize(name_conf, &(*test_ctx)->tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error loading TCTI: %s", name_conf);
        goto cleanup_test_ctx;
    }

    rc = tcti_proxy_initialize(NULL, &size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Proxy TCTI initialization failed (while getting context size): 0x%" PRIx32, rc);
        goto cleanup_tcti_ctx;
    }
    (*test_ctx)->tcti_proxy_ctx = malloc(size);
    if ((*test_ctx)->tcti_proxy_ctx == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for the proxy TCTI context", size);
        goto cleanup_tcti_ctx;
    }
    rc = tcti_proxy_initialize((*test_ctx)->tcti_proxy_ctx, &size, (*test_ctx)->tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Proxy TCTI initialization failed: 0x%" PRIx32, rc);
        goto cleanup_tcti_proxy_mem;
    }
    ((TSS2_TCTI_CONTEXT_PROXY *) (*test_ctx)->tcti_proxy_ctx)->state = forwarding;

    rc = Esys_Initialize(&(*test_ctx)->esys_ctx, (*test_ctx)->tcti_proxy_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_Initialize failed: 0x%" PRIx32, rc);
        goto cleanup_tcti_proxy_ctx;
    }

    rc = Esys_Startup((*test_ctx)->esys_ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        LOG_ERROR("Esys_Startup failed: 0x%" PRIx32, rc);
        goto cleanup_esys_ctx;
    }

    (*test_ctx)->tpm_state = malloc(sizeof(tpm_state));
    if (test_ctx == NULL) {
        LOG_ERROR("Failed to allocate 0x%zx bytes for tpm_state.", size);
        goto cleanup_esys_ctx;
    }

    return TPM2_RC_SUCCESS;

    free((*test_ctx)->tpm_state);

cleanup_esys_ctx:
    Esys_Finalize(&(*test_ctx)->esys_ctx);

cleanup_tcti_proxy_ctx:
    Tss2_Tcti_Finalize((*test_ctx)->tcti_proxy_ctx);

cleanup_tcti_proxy_mem:
    free((*test_ctx)->tcti_proxy_ctx);

cleanup_tcti_ctx:
    Tss2_TctiLdr_Finalize(&(*test_ctx)->tcti_ctx);

cleanup_test_ctx:
    free(*test_ctx);

fail:
    return EXIT_ERROR;
}

int
test_esys_checks_pre(TSS2_TEST_ESYS_CONTEXT *test_ctx)
{
    int ret;
    TSS2_RC rc;
    TSS2_SYS_CONTEXT *sys_context;

    rc = Esys_GetSysContext(test_ctx->esys_ctx, &sys_context);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("Error while getting System API context from Enhanced System API context.");
        return EXIT_ERROR;
    }

    LOG_DEBUG("Running System API pre-test checks: transient handles empty");
    ret = transient_empty(sys_context);
    if (ret != EXIT_SUCCESS) {
        LOG_ERROR("TPM contains transient objects.");
        return ret;
    }

    LOG_DEBUG("Running System API pre-test checks: dump handle capabilities");
    ret = dumpstate(sys_context, test_ctx->tpm_state, 0);
    if (ret != EXIT_SUCCESS) {
        LOG_ERROR("Error while dumping TPM state.");
        return ret;
    }

    return EXIT_SUCCESS;
}

int
test_esys_checks_post(TSS2_TEST_ESYS_CONTEXT *test_ctx)
{
    int ret;
    TSS2_RC rc;
    TSS2_SYS_CONTEXT *sys_context;

    rc = Esys_GetSysContext(test_ctx->esys_ctx, &sys_context);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("Error while getting System API context from Enhanced System API context.");
        return EXIT_ERROR;
    }

    LOG_DEBUG("Running System API post-test checks: dump capabilities");
    ret = dumpstate(sys_context, test_ctx->tpm_state, 1);
    if (ret != EXIT_SUCCESS) {
        LOG_ERROR("Error while performing TPM state checks.");
        return ret;
    }

    return EXIT_SUCCESS;
}

void
test_esys_teardown(TSS2_TEST_ESYS_CONTEXT *test_ctx)
{
    if (test_ctx) {
        free(test_ctx->tpm_state);
        Esys_Finalize(&test_ctx->esys_ctx);
        Tss2_Tcti_Finalize(test_ctx->tcti_proxy_ctx);
        free(test_ctx->tcti_proxy_ctx);
        Tss2_TctiLdr_Finalize(&test_ctx->tcti_ctx);
        free(test_ctx);
    }
}

#endif /* TEST_ESYS */

#ifdef TEST_FAPI
int
test_fapi_checks_pre(TSS2_TEST_FAPI_CONTEXT *test_ctx)
{
    return test_esys_checks_pre(&test_ctx->test_esys_ctx);
}

int
test_fapi_checks_post(TSS2_TEST_FAPI_CONTEXT *test_ctx)
{
    return test_esys_checks_post(&test_ctx->test_esys_ctx);
}
#endif /* TEST_FAPI */
