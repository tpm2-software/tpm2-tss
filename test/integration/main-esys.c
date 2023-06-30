/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_esys.h"

#include "tss2_tctildr.h"
#include "test-esys.h"
#include "tss2-esys/esys_int.h"
#define LOGMODULE test
#include "util/log.h"



#include "test-common.h"




/**
 * This program is a template for integration tests (ones that use the TCTI
 * and the ESYS contexts / API directly). It does nothing more than parsing
 * command line options that allow the caller (likely a script) to specify
 * which TCTI to use for the test.
 */
int
main(int argc, char *argv[])
{
    TSS2_TEST_ESYS_CONTEXT *test_esys_ctx;
    TSS2_RC rc;
    int ret;

    (void) argc;
    (void) argv;

    ret = test_esys_setup(&test_esys_ctx);
    if (ret != 0) {
        return ret;
    }

    ret = test_esys_checks_pre(test_esys_ctx);
    if (ret != 0) {
        return ret;
    }

    rc = test_invoke_esys(test_esys_ctx->esys_ctx);
    if (rc != 0 && rc != EXIT_SKIP) {
        LOG_ERROR("Test returned %08x", rc);
        return rc;
    }

    ret = test_esys_checks_post(test_esys_ctx);
    if (ret != 0) {
        return ret;
    }

    test_esys_teardown(test_esys_ctx);

    return rc;
}
