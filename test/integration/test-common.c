/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>                           // for PRIx32, uint8_t
#include <stdbool.h>                            // for bool
#include <stdio.h>                              // for NULL, size_t
#include <stdlib.h>                             // for free, malloc, EXIT_SU...
#include <string.h>                             // for memcmp

#include "test/integration/test-common-tcti.h"  // for tcti_proxy_initialize
#include "tss2_common.h"                        // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_mu.h"                            // for Tss2_MU_TPMS_CAPABILI...
#include "tss2_tctildr.h"                       // for Tss2_TctiLdr_Finalize
#include "tss2_tpm2_types.h"                    // for TPMS_CAPABILITY_DATA
#ifdef TEST_ESYS
#include "tss2_esys.h"                          // for Esys_Finalize, Esys_G...
#endif
#define LOGMODULE test
#include "test-common.h"
#include "util/log.h"                           // for LOG_ERROR, LOG_DEBUG


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

int fapi_tcti_state_backup_if_necessary(FAPI_CONTEXT *fapi_context, libtpms_state *state)
{
    TPM2_RC rc;
    int ret;
    TSS2_TCTI_CONTEXT *tcti;

    rc = Fapi_GetTcti(fapi_context, &tcti);
    return_if_error(rc, "Error Fapi_GetTcti");

    ret = tcti_state_backup_if_necessary(tcti, state);
    return_if_error(ret, "Error tcti_state_backup_if_necessary");

    return 0;
}

int fapi_tcti_state_restore_if_necessary(FAPI_CONTEXT *fapi_context, libtpms_state *state)
{
    TPM2_RC rc;
    int ret;
    TSS2_TCTI_CONTEXT *tcti;

    rc = Fapi_GetTcti(fapi_context, &tcti);
    return_if_error(rc, "Error Fapi_GetTcti");

    ret = tcti_state_restore_if_necessary(tcti, state);
    return_if_error(ret, "Error tcti_state_restore_if_necessary");

    return 0;
}

#endif /* TEST_FAPI */
