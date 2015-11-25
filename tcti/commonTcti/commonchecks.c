//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, 
// this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, 
// this list of conditions and the following disclaimer in the documentation 
// and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include "tpm20.h"
#include "tss2_sysapi_util.h"
#include "debug.h"

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC CommonSendChecks(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    uint8_t           *command_buffer     /* in */
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    
    if( tctiContext == NULL || command_buffer == NULL )
    {
        rval = TSS2_TCTI_RC_BAD_REFERENCE;
        goto returnFromCommonSendChecks;
    }        
    
    if( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage == TCTI_STAGE_SEND_COMMAND )
    {
        rval = TSS2_TCTI_RC_BAD_SEQUENCE;
        goto returnFromCommonSendChecks;
    }

    if( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->magic != TCTI_MAGIC ||
        ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->version != TCTI_VERSION )
    {
        rval = TSS2_TCTI_RC_BAD_CONTEXT;
        goto returnFromCommonSendChecks;
    }
    
returnFromCommonSendChecks:

    return rval;
}


TSS2_RC CommonReceiveChecks( 
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    size_t          *response_size,     /* out */
    unsigned char   *response_buffer    /* in */
    )
{
	TSS2_RC rval = TSS2_RC_SUCCESS;

    if( tctiContext == NULL || response_buffer == NULL || response_size == NULL )
    {
        rval = TSS2_TCTI_RC_BAD_REFERENCE;
        goto retCommonReceiveChecks;
    }        

    if( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage == TCTI_STAGE_RECEIVE_RESPONSE )
    {
        rval = TSS2_TCTI_RC_BAD_SEQUENCE;
        goto retCommonReceiveChecks;
    }

    if( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->magic != TCTI_MAGIC ||
        ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->version != TCTI_VERSION )
    {
        rval = TSS2_TCTI_RC_BAD_CONTEXT;
        goto retCommonReceiveChecks;
    }
    
retCommonReceiveChecks:

    return rval;
}