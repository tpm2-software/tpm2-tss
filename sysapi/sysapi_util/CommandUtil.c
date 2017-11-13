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

void InitSysContextFields(TSS2_SYS_CONTEXT *sysContext)
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

void InitSysContextPtrs(
    TSS2_SYS_CONTEXT *sysContext,
    size_t contextSize)
{
    SYS_CONTEXT->cmdBuffer = (UINT8 *)SYS_CONTEXT + sizeof(_TSS2_SYS_CONTEXT_BLOB);
    SYS_CONTEXT->maxCmdSize = contextSize - sizeof(_TSS2_SYS_CONTEXT_BLOB);
}

UINT32 GetCommandSize(TSS2_SYS_CONTEXT *sysContext)
{
    return BE_TO_HOST_32(SYS_REQ_HEADER->commandSize);
}

TSS2_RC CopyCommandHeader(TSS2_SYS_CONTEXT *sysContext, TPM2_CC commandCode)
{
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    SYS_CONTEXT->nextData = 0;
    SYS_CONTEXT->rval = TSS2_RC_SUCCESS;

    rval = Tss2_MU_TPM2_ST_Marshal(TPM2_ST_NO_SESSIONS, SYS_CONTEXT->cmdBuffer,
                                  SYS_CONTEXT->maxCmdSize,
                                  &SYS_CONTEXT->nextData);
    if (rval)
        return rval;

    SYS_REQ_HEADER->commandCode = HOST_TO_BE_32(commandCode);
    SYS_CONTEXT->nextData = sizeof(TPM20_Header_In);
    return rval;
}

TSS2_RC CommonPreparePrologue(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2_CC commandCode)
{
	int numCommandHandles;
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    InitSysContextFields(sysContext);

    /* Need to check stage here. */
    if (SYS_CONTEXT->previousStage != CMD_STAGE_INITIALIZE &&
        SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE &&
        SYS_CONTEXT->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    rval = CopyCommandHeader(sysContext, commandCode);
    if (rval)
        return rval;

    SYS_CONTEXT->commandCode = commandCode;
    SYS_CONTEXT->numResponseHandles = GetNumResponseHandles(commandCode);
    SYS_CONTEXT->rspParamsSize = (UINT32 *)(SYS_CONTEXT->cmdBuffer +
                                     sizeof(TPM20_Header_Out) +
                                     (GetNumResponseHandles(commandCode) * sizeof(UINT32)));

    numCommandHandles = GetNumCommandHandles(commandCode);
    SYS_CONTEXT->cpBuffer = SYS_CONTEXT->cmdBuffer +
                            SYS_CONTEXT->nextData +
                            (numCommandHandles * sizeof(UINT32));
    return rval;
}

TSS2_RC CommonPrepareEpilogue(TSS2_SYS_CONTEXT *sysContext)
{
    SYS_CONTEXT->cpBufferUsedSize = (SYS_CONTEXT->cmdBuffer + SYS_CONTEXT->nextData) -
                                     SYS_CONTEXT->cpBuffer;
    SYS_REQ_HEADER->commandSize = HOST_TO_BE_32(SYS_CONTEXT->nextData);
    SYS_CONTEXT->previousStage = CMD_STAGE_PREPARE;

    return TSS2_RC_SUCCESS;
}

TSS2_RC CommonComplete(TSS2_SYS_CONTEXT *sysContext)
{
    UINT32 rspSize;
    TPM2_ST tag;
    size_t next = 0;
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rspSize = BE_TO_HOST_32(SYS_RESP_HEADER->responseSize);

    if(rspSize > SYS_CONTEXT->maxCmdSize) {
        SYS_CONTEXT->rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
        return TSS2_SYS_RC_MALFORMED_RESPONSE;
    }

    /*
     * NOTE: should this depend on the status of previous
     * API call? i.e. SYS_CONTEXT->rval != TSS2_RC_SUCCESS
     */
    if (SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE ||
        SYS_CONTEXT->rval != TSS2_RC_SUCCESS)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    SYS_CONTEXT->nextData = (UINT8 *)SYS_CONTEXT->rspParamsSize -
                                     SYS_CONTEXT->cmdBuffer;

    rval = Tss2_MU_TPM2_ST_Unmarshal(SYS_CONTEXT->cmdBuffer,
                                    SYS_CONTEXT->maxCmdSize,
                                    &next, &tag);
    if (rval)
        return rval;

    /* Save response params size */
    if (tag == TPM2_ST_SESSIONS) {
        rval = Tss2_MU_UINT32_Unmarshal(SYS_CONTEXT->cmdBuffer,
                                        SYS_CONTEXT->maxCmdSize,
                                        &SYS_CONTEXT->nextData,
                                        &SYS_CONTEXT->rpBufferUsedSize);
        if (rval)
            return rval;
    }

    SYS_CONTEXT->rpBuffer = SYS_CONTEXT->cmdBuffer + SYS_CONTEXT->nextData;

    if (tag != TPM2_ST_SESSIONS) {
        SYS_CONTEXT->rpBufferUsedSize = rspSize -
                (SYS_CONTEXT->rpBuffer - SYS_CONTEXT->cmdBuffer);
    }

    return rval;
}

TSS2_RC CommonOneCall(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
        return SYS_CONTEXT->rval;

    if (cmdAuthsArray) {
        rval = Tss2_Sys_SetCmdAuths(sysContext, cmdAuthsArray);
        if (rval)
            return rval;
    }

    rval = Tss2_Sys_Execute(sysContext);
    if (rval)
        return rval;

    if (SYS_CONTEXT->rsp_header.responseCode)
        return SYS_CONTEXT->rsp_header.responseCode;

    if (BE_TO_HOST_16(SYS_RESP_HEADER->tag) == TPM2_ST_SESSIONS && rspAuthsArray)
        rval = Tss2_Sys_GetRspAuths(sysContext, rspAuthsArray);

    return rval;
}

TSS2_RC CommonOneCallForNoResponseCmds(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    TSS2_RC rval;

    rval = CommonOneCall(sysContext, cmdAuthsArray, rspAuthsArray);
    if(rval)
        return rval;

    return CommonComplete(sysContext);
}
