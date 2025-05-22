/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdbool.h>
#include <stdlib.h>

#define LOGMODULE test
#include "tss2_sys.h"
#include "tss2_tcti.h"
#include "util/log.h"
#include "test.h"
#include "tss2-sys/sysapi_util.h"
#include "tcti/tcti-fuzzing.h"

#include "test-common.h"

int
LLVMFuzzerTestOneInput (
        const uint8_t *Data,
        size_t Size)
{
    TSS2_TEST_SYS_CONTEXT *test_sys_ctx;
    TSS2_TCTI_FUZZING_CONTEXT *tcti_fuzzing = NULL;
    TSS2_RC rc;
    int ret;

    ret = test_sys_setup(&test_sys_ctx, true);
    if (ret != 0) {
        return -1;
    }

    tcti_fuzzing = (TSS2_TCTI_FUZZING_CONTEXT*) test_sys_ctx->tcti_ctx;
    tcti_fuzzing->data = Data;
    tcti_fuzzing->size = Size;

    rc = test_invoke(test_sys_ctx->sys_ctx);
    if (rc != 0) {
        ret = -1;
        goto cleanup;
    }

    ret = 0;

cleanup:
    test_sys_teardown(test_sys_ctx);

    return ret;
}
