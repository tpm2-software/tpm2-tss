/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdio.h>        // for NULL
#include <stdlib.h>       // for exit

#include "tss2_common.h"  // for TSS2_ABI_VERSION, TSS2_SYS_RC_ABI_MISMATCH
#include "tss2_sys.h"     // for Tss2_Sys_Initialize, Tss2_Sys_GetContextSize
#include "tss2_tcti.h"    // for TSS2_TCTI_CONTEXT

#define LOGMODULE test
#include "test-common.h"  // for TEST_ABI_VERSION, TSSWG_INTEROP, TSS_SYS_FI...
#include "test.h"         // for test_invoke
#include "util/log.h"     // for LOG_ERROR, LOG_INFO

/**
 */
int
test_invoke (TSS2_SYS_CONTEXT *sys_context)
{
    TSS2_RC rc;
    UINT32 contextSize;
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_ABI_VERSION tstAbiVersion = TEST_ABI_VERSION;

    LOG_INFO( "ABI NEGOTIATION TESTS" );

    /* Get the size needed for sys context structure. */
    contextSize = Tss2_Sys_GetContextSize( 0 );

    rc = Tss2_Sys_GetTctiContext (sys_context, &tcti_context);
    if( rc != TSS2_RC_SUCCESS )
    {
        LOG_ERROR("ABIVersion FAILED! Response Code : %x", rc);
        exit(1);
    }

    /* Initialize the system context structure. */
    tstAbiVersion.tssCreator = 0xF0000000;
    rc = Tss2_Sys_Initialize( sys_context, contextSize, tcti_context, &tstAbiVersion );
    if( rc != TSS2_SYS_RC_ABI_MISMATCH )
    {
        LOG_ERROR("ABIVersion FAILED! Response Code : %x", rc);
        exit(1);
    }

    tstAbiVersion.tssCreator = TSSWG_INTEROP;
    tstAbiVersion.tssFamily = 0xF0000000;
    rc = Tss2_Sys_Initialize( sys_context, contextSize, tcti_context, &tstAbiVersion );
    if( rc != TSS2_SYS_RC_ABI_MISMATCH )
    {
        LOG_ERROR("ABIVersion FAILED! Response Code : %x", rc);
        exit(1);
    }

    tstAbiVersion.tssFamily = TSS_SYS_FIRST_FAMILY;
    tstAbiVersion.tssLevel = 0xF0000000;
    rc = Tss2_Sys_Initialize( sys_context, contextSize, tcti_context, &tstAbiVersion );
    if( rc != TSS2_SYS_RC_ABI_MISMATCH )
    {
        LOG_ERROR("ABIVersion FAILED! Response Code : %x", rc);
        exit(1);
    }

    tstAbiVersion.tssLevel = TSS_SYS_FIRST_LEVEL;
    tstAbiVersion.tssVersion = 0xF0000000;
    rc = Tss2_Sys_Initialize( sys_context, contextSize, tcti_context, &tstAbiVersion );
    if( rc != TSS2_SYS_RC_ABI_MISMATCH )
    {
        LOG_ERROR("ABIVersion FAILED! Response Code : %x", rc);
    }


    LOG_INFO("ABIVersion Test Passed!");
    return 0;
}
