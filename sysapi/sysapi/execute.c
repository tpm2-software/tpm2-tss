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

#include "sapi/tpm20.h"
#include "sysapi_util.h"
#include "tss2_endian.h"

TSS2_RC Tss2_Sys_ExecuteAsync(
    TSS2_SYS_CONTEXT 		*sysContext
    )
{
    TSS2_RC  rval = TSS2_RC_SUCCESS;

    if( sysContext == 0 )
    {
        rval = TSS2_SYS_RC_BAD_REFERENCE;
    }
    else if( SYS_CONTEXT->previousStage != CMD_STAGE_PREPARE )
    {
        rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else
    {
        rval = tss2_tcti_transmit(SYS_CONTEXT->tctiContext,
                                  HOST_TO_BE_32(((TPM20_Header_In *)SYS_CONTEXT->tpmInBuffPtr)->commandSize),
                                  SYS_CONTEXT->tpmInBuffPtr);
    }

    if( rval == TSS2_RC_SUCCESS )
    {
        SYS_CONTEXT->previousStage = CMD_STAGE_SEND_COMMAND;
    }
    return rval;
}

TSS2_RC Tss2_Sys_ExecuteFinish(
    TSS2_SYS_CONTEXT 		*sysContext,
    int32_t                 timeout
    )
{
    TSS2_RC  rval = TSS2_RC_SUCCESS;
    size_t responseSize = 0;
    UINT8 tpmError = 0;

    if( sysContext == 0 )
    {
        rval = TSS2_SYS_RC_BAD_REFERENCE;
    }
    else if( SYS_CONTEXT->previousStage != CMD_STAGE_SEND_COMMAND )
    {
        rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else
    {
        responseSize = SYS_CONTEXT->maxResponseSize;
        rval = tss2_tcti_receive (SYS_CONTEXT->tctiContext,
                                  &responseSize,
                                  SYS_CONTEXT->tpmOutBuffPtr,
                                  timeout);
    }

    if( rval == TSS2_RC_SUCCESS )
    {
        if( responseSize < sizeof( TPM20_ErrorResponse ) )
        {
            rval = TSS2_SYS_RC_INSUFFICIENT_RESPONSE;
        }
        else if( responseSize > SYS_CONTEXT->maxResponseSize )
        {
            rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
        }
        else
        {
            SYS_CONTEXT->rval = TSS2_RC_SUCCESS;

            /*
             * Unmarshal the tag, response size, and response code as soon
             * as possible. Later processing code should get this data from
             * the TPM20_Rsp_Header in the context structure. No need to
             * unmarshal this stuff again.
             */
            SYS_CONTEXT->nextData = 0;
            Unmarshal_TPM_ST (SYS_CONTEXT->tpmOutBuffPtr,
                              SYS_CONTEXT->maxCommandSize,
                              &SYS_CONTEXT->nextData,
                              &SYS_CONTEXT->rsp_header.tag,
                              &SYS_CONTEXT->rval);
            Unmarshal_UINT32 (SYS_CONTEXT->tpmOutBuffPtr,
                              SYS_CONTEXT->maxCommandSize,
                              &SYS_CONTEXT->nextData,
                              &SYS_CONTEXT->rsp_header.size,
                              &(SYS_CONTEXT->rval) );
            Unmarshal_UINT32 (SYS_CONTEXT->tpmOutBuffPtr,
                              SYS_CONTEXT->maxCommandSize,
                              &SYS_CONTEXT->nextData,
                              &SYS_CONTEXT->rsp_header.rsp_code,
                              &SYS_CONTEXT->rval);
            if (SYS_CONTEXT->rsp_header.size < sizeof(TPM20_Header_Out) - 1)
            {
                rval = SYS_CONTEXT->rval = TSS2_SYS_RC_INSUFFICIENT_RESPONSE;
            }
            else
            {
                if (SYS_CONTEXT->rsp_header.rsp_code == TSS2_RC_SUCCESS) {
                    if( SYS_CONTEXT->rval != TPM_RC_SUCCESS )
                    {
                        tpmError = 1;
                        rval = SYS_CONTEXT->rval;
                    }
                } else {
                    rval = SYS_CONTEXT->rsp_header.rsp_code;
                    SYS_CONTEXT->rval = SYS_CONTEXT->rsp_header.rsp_code;
                }
            }
        }

        // If we received a TPM error other than CANCELED or if we didn't receive enough response bytes,
        // reset SAPI state machine to CMD_STAGE_PREPARE.  There's nothing
        // else we can do for current command.
        if( ( tpmError && rval != TPM_RC_CANCELED ) || ( rval == TSS2_SYS_RC_INSUFFICIENT_RESPONSE ) )
        {
            SYS_CONTEXT->previousStage = CMD_STAGE_PREPARE;
        }
        else
        {
            SYS_CONTEXT->previousStage = CMD_STAGE_RECEIVE_RESPONSE;
        }
    }
    else if( rval == TSS2_TCTI_RC_INSUFFICIENT_BUFFER )
    {
        // Changed error code to what it should be.
        rval = TSS2_SYS_RC_INSUFFICIENT_CONTEXT;
    }

    return rval;
}



TSS2_RC Tss2_Sys_Execute(
    TSS2_SYS_CONTEXT 		*sysContext
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = Tss2_Sys_ExecuteAsync( sysContext );
    if( rval == TSS2_RC_SUCCESS )
    {
        rval = Tss2_Sys_ExecuteFinish( sysContext, TSS2_TCTI_TIMEOUT_BLOCK );
    }
    return rval;
}
