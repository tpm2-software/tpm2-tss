/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ***********************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include "tss2_sys.h"

#include "tss2-sys/sysapi_util.h"

#define LOGMODULE test
#include "util/log.h"
#include "test.h"
/**
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;

    // NOTE: this should never be done in real applications.
    // It is only done here for test purposes.
    TSS2_TCTI_CONTEXT_COMMON_V2 tctiContext;

    LOG_INFO("Sys_Initialize tests started.");

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)0, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_REFERENCE  ) {
        LOG_ERROR("Sys_Initialize context NULL test FAILED! Response Code : %x", rc);
        exit(1);
    }

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)0, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_REFERENCE  ) {
        LOG_ERROR("Sys_Initialize tcti  NULL test FAILED! Response Code : %x", rc);
        exit(1);
    }

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, 10, (TSS2_TCTI_CONTEXT *)1, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_INSUFFICIENT_CONTEXT ) {
        LOG_ERROR("Sys_Initialize insufficient context FAILED! Response Code : %x", rc);
        exit(1);
    }

    // NOTE: don't do this in real applications.
    TSS2_TCTI_RECEIVE (&tctiContext) = (TSS2_TCTI_RECEIVE_FCN)1;
    TSS2_TCTI_TRANSMIT (&tctiContext) = (TSS2_TCTI_TRANSMIT_FCN)0;

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContext, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_TCTI_STRUCTURE ) {
        LOG_ERROR("Sys_Initialize FAILED! Response Code : %x", rc);
        exit(1);
    }

    // NOTE: don't do this in real applications.
    TSS2_TCTI_RECEIVE (&tctiContext) = (TSS2_TCTI_RECEIVE_FCN)0;
    TSS2_TCTI_TRANSMIT (&tctiContext) = (TSS2_TCTI_TRANSMIT_FCN)1;

    rc = Tss2_Sys_Initialize( (TSS2_SYS_CONTEXT *)1, sizeof( _TSS2_SYS_CONTEXT_BLOB ), (TSS2_TCTI_CONTEXT *)&tctiContext, (TSS2_ABI_VERSION *)1 );
    if( rc != TSS2_SYS_RC_BAD_TCTI_STRUCTURE ) {
        LOG_ERROR("Sys_Initialize FAILED! Response Code : %x", rc);
        exit(1);
    }

    LOG_INFO("Sys_Initialize Test Passed!");
    return 0;
}
