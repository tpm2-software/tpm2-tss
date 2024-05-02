/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdio.h>            // for NULL
#include <stdlib.h>           // for exit

#include "tss2_common.h"      // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_SYS_RC_B...
#include "tss2_sys.h"         // for Tss2_Sys_StirRandom, TSS2_SYS_CONTEXT
#include "tss2_tpm2_types.h"  // for TPM2B_SENSITIVE_DATA

#define LOGMODULE test
#include "test.h"             // for test_invoke
#include "util/log.h"         // for LOG_ERROR, LOG_INFO

/**
 * This program contains integration test for SYS Tss2_Sys_StirRandom.
 * Since StirRandom is quite simple we can only check for success if we
 * supply correct parameters.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sys_context)
{
    TSS2_RC rc;
    TPM2B_SENSITIVE_DATA inData  = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    LOG_INFO("StirRandom tests started.");
    /* Check invalid context */
    rc = Tss2_Sys_StirRandom(NULL, 0, NULL, 0);
    if (rc != TSS2_SYS_RC_BAD_REFERENCE) {
        LOG_ERROR("StirRandom (ctx) FAILED! Response Code : %x", rc);
        exit(1);
    }

    /* check empty input data */
    rc = Tss2_Sys_StirRandom(sys_context, 0, NULL, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("StirRandom (empty) FAILED! Response Code : %x", rc);
        exit(1);
    }

    /* check with correct input data*/
    rc = Tss2_Sys_StirRandom(sys_context, 0, &inData, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("StirRandom (indata) FAILED! Response Code : %x", rc);
        exit(1);
    }
    LOG_INFO("StirRandom Test Passed!");
    return 0;
}
