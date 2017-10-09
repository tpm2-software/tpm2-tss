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

void InitSysContextFields(
    TSS2_SYS_CONTEXT *sysContext
    )
{
    SYS_CONTEXT->tpmVersionInfoValid = 0;
    SYS_CONTEXT->decryptAllowed = 0;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->decryptNull = 0;
    SYS_CONTEXT->authAllowed = 0;
    SYS_CONTEXT->decryptSession = 0;
    SYS_CONTEXT->encryptSession = 0;
    SYS_CONTEXT->prepareCalledFromOneCall = 0;
    SYS_CONTEXT->completeCalledFromOneCall = 0;
    SYS_CONTEXT->nextData = 0;
    SYS_CONTEXT->rpBufferUsedSize = 0;
    SYS_CONTEXT->rval = TSS2_RC_SUCCESS;
}
/**
 * Initialize pointers to the various memory blocks / buffers in the opaque
 * area of the TSS2_SYS_CONTEXT structure.
 *
 * tpmInBufferPtr: pointer to the memory area where we build command buffers
 *   that we send to the TPM
 * tpmOutBufferPtrs: pointer to the memory area where we store the TPMs
 *   response
 * maxComamndSize / maxResponseSize: the size of these memory areas.
 *
 * NOTE: It should only be necessary to invoke this function once for any
 * given sys context.
 */
void InitSysContextPtrs(
    TSS2_SYS_CONTEXT   *sysContext,
    size_t              contextSize
    )
{
    SYS_CONTEXT->tpmInBuffPtr =
        (UINT8 *)SYS_CONTEXT + sizeof( _TSS2_SYS_CONTEXT_BLOB );
    SYS_CONTEXT->tpmOutBuffPtr = SYS_CONTEXT->tpmInBuffPtr;
    SYS_CONTEXT->maxCommandSize =
        contextSize - ((UINT8 *)SYS_CONTEXT->tpmInBuffPtr - (UINT8 *)SYS_CONTEXT);
    SYS_CONTEXT->maxResponseSize = SYS_CONTEXT->maxCommandSize;
}


UINT32 GetCommandSize( TSS2_SYS_CONTEXT *sysContext )
{
    return BE_TO_HOST_32(SYS_REQ_HEADER->commandSize);
}

void CopyCommandHeader( _TSS2_SYS_CONTEXT_BLOB *sysContext, TPM_CC commandCode )
{
    SYS_CONTEXT->rval = TSS2_RC_SUCCESS;
    SYS_CONTEXT->nextData = 0;

    Marshal_TPM_ST (SYS_CONTEXT->tpmInBuffPtr,
                    SYS_CONTEXT->maxCommandSize,
                    &(SYS_CONTEXT->nextData),
                    TPM_ST_NO_SESSIONS,
                    &(SYS_CONTEXT->rval));

  SYS_REQ_HEADER->commandCode = BE_TO_HOST_32(commandCode);

  SYS_CONTEXT->rval = TSS2_RC_SUCCESS;

  SYS_CONTEXT->nextData = sizeof(TPM20_Header_In);
}

TPM_RC FinishCommand( _TSS2_SYS_CONTEXT_BLOB *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    UINT32 *responseSize )
{
    if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
        return SYS_CONTEXT->rval;

    SYS_CONTEXT->rval = Tss2_Sys_Execute((TSS2_SYS_CONTEXT *)sysContext);

    return SYS_CONTEXT->rval;
}

// Common to all _Prepare
TSS2_RC CommonPreparePrologue(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_CC commandCode
)
{
	int numCommandHandles;

    if( sysContext == NULL )
    {
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    InitSysContextFields( sysContext );

    // Need to check stage here.
    if( SYS_CONTEXT->previousStage != CMD_STAGE_INITIALIZE &&
            SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE &&
            SYS_CONTEXT->previousStage != CMD_STAGE_PREPARE  )
    {
        SYS_CONTEXT->rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else
    {
        CopyCommandHeader( SYS_CONTEXT, commandCode );

        SYS_CONTEXT->numResponseHandles = GetNumResponseHandles( commandCode );

        SYS_CONTEXT->commandCodeSwapped = HOST_TO_BE_32(commandCode);

        SYS_CONTEXT->rspParamsSize = (UINT32 *)(SYS_CONTEXT->tpmOutBuffPtr +
                                     sizeof(TPM20_Header_Out) +
                                     (GetNumResponseHandles(commandCode) * sizeof(UINT32)));

        numCommandHandles = GetNumCommandHandles( commandCode );
        SYS_CONTEXT->cpBuffer = SYS_CONTEXT->tpmInBuffPtr + SYS_CONTEXT->nextData + (numCommandHandles * sizeof(UINT32));
    }

    return SYS_CONTEXT->rval;
}

// Common to all _Prepare
TSS2_RC CommonPrepareEpilogue(
    TSS2_SYS_CONTEXT *sysContext
)
{
   if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
   {
       return SYS_CONTEXT->rval;
   }
   SYS_CONTEXT->cpBufferUsedSize = (SYS_CONTEXT->tpmInBuffPtr + SYS_CONTEXT->nextData) - SYS_CONTEXT->cpBuffer;

   // Set current command size.
   SYS_REQ_HEADER->commandSize = HOST_TO_BE_32(SYS_CONTEXT->nextData);

   SYS_CONTEXT->previousStage = CMD_STAGE_PREPARE;

   return SYS_CONTEXT->rval;
}

// Common to all _Complete
TSS2_RC CommonComplete( TSS2_SYS_CONTEXT *sysContext )
{
    UINT32 rspSize;

    if( sysContext == NULL )
    {
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    else
    {
        rspSize = BE_TO_HOST_32(SYS_RESP_HEADER->responseSize);
    }

    if( SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE || SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
    {
        SYS_CONTEXT->rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else if( rspSize > SYS_CONTEXT->maxResponseSize )
    {
        SYS_CONTEXT->rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
    }
    else
    {
        TPM_ST tag = 0;
        SYS_CONTEXT->nextData = (UINT8 *)SYS_CONTEXT->rspParamsSize - SYS_CONTEXT->tpmOutBuffPtr;

        // Save response params size if command has authorization area.
        size_t tmp = 0;
        Unmarshal_TPM_ST (SYS_CONTEXT->tpmOutBuffPtr,
                          SYS_CONTEXT->maxResponseSize,
                          &tmp, &tag, &SYS_CONTEXT->rval);
        if( tag == TPM_ST_SESSIONS )
        {
            Unmarshal_UINT32( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &( SYS_CONTEXT->nextData ),
                    &( SYS_CONTEXT->rpBufferUsedSize ), &(SYS_CONTEXT->rval ) );
        }

        SYS_CONTEXT->rpBuffer = SYS_CONTEXT->tpmOutBuffPtr + SYS_CONTEXT->nextData;

        // Save response params size if command does not have an authorization area.
        if (BE_TO_HOST_16(SYS_RESP_HEADER->tag) != TPM_ST_SESSIONS)
        {
            SYS_CONTEXT->rpBufferUsedSize = rspSize - ( SYS_CONTEXT->rpBuffer - SYS_CONTEXT->tpmOutBuffPtr );
        }
    }

    return SYS_CONTEXT->rval;
}

TSS2_RC CommonOneCall(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    )
{
    UINT32      responseSize;

    if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
        return SYS_CONTEXT->rval;

    if( cmdAuthsArray != 0 )
    {
        SYS_CONTEXT->rval = Tss2_Sys_SetCmdAuths( sysContext, cmdAuthsArray );
    }

    if( SYS_CONTEXT->rval == TSS2_RC_SUCCESS )
    {
        SYS_CONTEXT->rval = FinishCommand( SYS_CONTEXT, cmdAuthsArray, &responseSize );

        if ( SYS_CONTEXT->rval == TSS2_RC_SUCCESS )
        {
            if (SYS_CONTEXT->rsp_header.responseCode == TPM_RC_SUCCESS)
            {
                if (BE_TO_HOST_16(SYS_RESP_HEADER->tag) == TPM_ST_SESSIONS && rspAuthsArray != 0)
                {
                    SYS_CONTEXT->rval = Tss2_Sys_GetRspAuths( sysContext, rspAuthsArray );
                }
            }
        }
    }
    return SYS_CONTEXT->rval;
}


TSS2_RC  CommonOneCallForNoResponseCmds(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = CommonOneCall(sysContext, cmdAuthsArray, rspAuthsArray);

    if(rval == TSS2_RC_SUCCESS)
        rval = CommonComplete(sysContext);

    return rval;
}

