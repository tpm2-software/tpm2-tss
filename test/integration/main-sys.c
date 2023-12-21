/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>

#define LOGMODULE test
#include "tss2_tctildr.h"
#include "tss2_sys.h"
#include "util/log.h"
#include "test.h"

#include "test-common.h"

/**
 * This program is a template for integration tests (ones that use the TCTI
 * and the SYS ctxs / API directly). It does nothing more than parsing
 * command line options that allow the caller (likely a script) to specify
 * which TCTI to use for the test.
 */
int
main (int   argc,
      char *argv[])
{
    TSS2_TEST_SYS_CONTEXT *test_sys_ctx;
    TSS2_RC rc;
    int ret;

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
    if (rc != 0 && ret != 77) {
        LOG_ERROR("Test returned %08x", rc);
        return rc;
    }

    ret = test_sys_checks_post(test_sys_ctx);
    if (ret != 0) {
        return ret;
    }

    test_sys_teardown(test_sys_ctx);

    return rc;
}
