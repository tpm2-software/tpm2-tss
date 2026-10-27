/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 * Copyright (c) 2026
 * All rights reserved.
 *
 * Shared main() for all generated SYS-API fuzz targets. Initializes the
 * fuzzing TCTI directly (no environment variable, no TCTI loader) so
 * the targets run anywhere, treats API error codes as normal fuzz
 * outcomes instead of exiting, and clamps the input to the SAPI
 * context buffer capacity (the fuzzing TCTI receive callback memcpy's
 * without a capacity check of its own).
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdbool.h>
#include <stdlib.h>

#define LOGMODULE test
#include "tcti/tcti-fuzzing.h"
#include "tss2_tcti_fuzzing.h"
#include "test.h"
#include "test-common.h"
#include "tss2-sys/sysapi_util.h"
#include "tss2_sys.h"
#include "tss2_tcti.h"
#include "util/log.h"

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    TSS2_TCTI_CONTEXT         *tcti_ctx = NULL;
    TSS2_TCTI_FUZZING_CONTEXT *tcti_fuzzing = NULL;
    TSS2_SYS_CONTEXT          *sys_ctx = NULL;
    TSS2_SYS_CONTEXT_BLOB     *ctx = NULL;
    TSS2_ABI_VERSION           abi_version = TEST_ABI_VERSION;
    TSS2_RC                    rc;
    size_t                     tcti_size = 0;
    size_t                     sys_size;

    /* Set up the fuzzing TCTI directly (no TPM20TEST_TCTI env, no loader). */
    rc = Tss2_Tcti_Fuzzing_Init(NULL, &tcti_size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        return 0;
    }
    tcti_ctx = calloc(1, tcti_size);
    if (tcti_ctx == NULL) {
        return 0;
    }
    rc = Tss2_Tcti_Fuzzing_Init(tcti_ctx, &tcti_size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        free(tcti_ctx);
        return 0;
    }

    sys_size = Tss2_Sys_GetContextSize(0);
    sys_ctx = calloc(1, sys_size);
    if (sys_ctx == NULL) {
        free(tcti_ctx);
        return 0;
    }
    rc = Tss2_Sys_Initialize(sys_ctx, sys_size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        free(sys_ctx);
        free(tcti_ctx);
        return 0;
    }
    ctx = syscontext_cast(sys_ctx);
    if (ctx != NULL) {
        /* Clamp to the context buffer capacity. */
        if (Size > ctx->maxCmdSize) {
            Size = ctx->maxCmdSize;
        }

        tcti_fuzzing = tcti_fuzzing_context_cast(tcti_ctx);
        tcti_fuzzing->data = Data;
        tcti_fuzzing->size = Size;

        /* Errors from the API under fuzz are normal outcomes, not exits. */
        (void) test_invoke(sys_ctx);
    }

    Tss2_Sys_Finalize(sys_ctx);
    free(sys_ctx);
    free(tcti_ctx);

    return 0; // Non-zero return values are reserved for future use.
}
