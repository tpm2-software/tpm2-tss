/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>       // for exit

#include "tss2_common.h"  // for TSS2_RC_SUCCESS, TSS2_RC
#include "tss2_sys.h"     // for Tss2_Sys_SelfTest, TSS2_SYS_CONTEXT

#define LOGMODULE test
#include "test.h"         // for YES, NO, test_invoke
#include "util/log.h"     // for LOG_ERROR, LOG_INFO

/*
 * This program contains integration test for SYS Tss2_Sys_SelfTest
 * that perform test of its capabilities. This program is calling
 * SelfTest SYS and make sure the response code are success
 * when fullTest set as YES and when it is set as NO.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sys_context)
{
    TSS2_RC rc;
    LOG_INFO( "SelfTest tests started." );
    rc = Tss2_Sys_SelfTest( sys_context, 0, YES, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("SelfTest FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    rc = Tss2_Sys_SelfTest( sys_context, 0, NO, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("SelfTest FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    rc = Tss2_Sys_SelfTest(sys_context, 0, YES, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("SelfTest FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_INFO("SelfTest tests passed.");
    return 0;
}
