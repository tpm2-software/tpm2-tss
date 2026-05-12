/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h> // for EXIT_FAILURE, EXIT_SUCCESS

#define LOGMODULE test
#include "test-common.h"   // for test_sys_checks_post, test_sys_checks_pre
#include "test.h"          // for test_invoke
#include "tss2_common.h"   // for TSS2_RC
#include "util/aux_util.h" // for UNUSED
#include "util/log.h"      // for LOG_ERROR

/**
 * This program is a template for integration tests (ones that use the TCTI
 * and the SYS ctxs / API directly). It does nothing more than parsing
 * command line options that allow the caller (likely a script) to specify
 * which TCTI to use for the test.
 */
int
main(int argc, char *argv[]) {
    TSS2_TEST_SYS_CONTEXT *test_sys_ctx;
    TSS2_RC                rc;
    int                    ret;

    UNUSED(argc);
    UNUSED(argv);

    ret = test_sys_setup(&test_sys_ctx);
    if (ret != 0) {
        return ret;
    }

    ret = test_sys_checks_pre(test_sys_ctx);
    if (ret != 0) {
        return ret;
    }

    rc = test_invoke(test_sys_ctx->sys_ctx);
    if (rc != 0 && rc != 77) {
        test_sys_teardown(test_sys_ctx);
        LOG_ERROR("Test returned %08x", rc);
        return EXIT_FAILURE;
    }

    ret = test_sys_checks_post(test_sys_ctx);
    if (ret != 0) {
        test_sys_teardown(test_sys_ctx);
        return ret;
    }

    test_sys_teardown(test_sys_ctx);

    return EXIT_SUCCESS;
}
