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

void InitSysContextFields(_TSS2_SYS_CONTEXT_BLOB *ctx)
{
    ctx->tpmVersionInfoValid = 0;
    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->decryptNull = 0;
    ctx->authAllowed = 0;
    ctx->decryptSession = 0;
    ctx->encryptSession = 0;
    ctx->prepareCalledFromOneCall = 0;
    ctx->completeCalledFromOneCall = 0;
    ctx->nextData = 0;
    ctx->rval = TSS2_RC_SUCCESS;
}

void InitSysContextPtrs(
    _TSS2_SYS_CONTEXT_BLOB *ctx,
    size_t contextSize)
{
    ctx->cmdBuffer = (UINT8 *)ctx + sizeof(_TSS2_SYS_CONTEXT_BLOB);
    ctx->maxCmdSize = contextSize - sizeof(_TSS2_SYS_CONTEXT_BLOB);
}

UINT32 GetCommandSize(_TSS2_SYS_CONTEXT_BLOB *ctx)
{
    return BE_TO_HOST_32(req_header_from_cxt(ctx)->commandSize);
}

TSS2_RC CopyCommandHeader(_TSS2_SYS_CONTEXT_BLOB *ctx, TPM2_CC commandCode)
{
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    ctx->nextData = 0;
    ctx->rval = TSS2_RC_SUCCESS;

    rval = Tss2_MU_TPM2_ST_Marshal(TPM2_ST_NO_SESSIONS, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    req_header_from_cxt(ctx)->commandCode = HOST_TO_BE_32(commandCode);
    ctx->nextData = sizeof(TPM20_Header_In);
    return rval;
}

TSS2_RC CommonPreparePrologue(
    _TSS2_SYS_CONTEXT_BLOB *ctx,
    TPM2_CC commandCode)
{
	int numCommandHandles;
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    InitSysContextFields(ctx);

    /* Need to check stage here. */
    if (ctx->previousStage != CMD_STAGE_INITIALIZE &&
        ctx->previousStage != CMD_STAGE_RECEIVE_RESPONSE &&
        ctx->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    rval = CopyCommandHeader(ctx, commandCode);
    if (rval)
        return rval;

    ctx->commandCode = commandCode;
    ctx->numResponseHandles = GetNumResponseHandles(commandCode);
    ctx->rspParamsSize = (UINT32 *)(ctx->cmdBuffer + sizeof(TPM20_Header_Out) +
                         (GetNumResponseHandles(commandCode) * sizeof(UINT32)));

    numCommandHandles = GetNumCommandHandles(commandCode);
    ctx->cpBuffer = ctx->cmdBuffer + ctx->nextData +
                                     (numCommandHandles * sizeof(UINT32));
    return rval;
}

TSS2_RC CommonPrepareEpilogue(_TSS2_SYS_CONTEXT_BLOB *ctx)
{
    ctx->cpBufferUsedSize = ctx->cmdBuffer + ctx->nextData - ctx->cpBuffer;
    req_header_from_cxt(ctx)->commandSize = HOST_TO_BE_32(ctx->nextData);
    ctx->previousStage = CMD_STAGE_PREPARE;

    return TSS2_RC_SUCCESS;
}

TSS2_RC CommonComplete(_TSS2_SYS_CONTEXT_BLOB *ctx)
{
    UINT32 rspSize;
    TPM2_ST tag;
    size_t next = 0;
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rspSize = BE_TO_HOST_32(resp_header_from_cxt(ctx)->responseSize);

    if(rspSize > ctx->maxCmdSize) {
        ctx->rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
        return TSS2_SYS_RC_MALFORMED_RESPONSE;
    }

    /*
     * NOTE: should this depend on the status of previous
     * API call? i.e. ctx->rval != TSS2_RC_SUCCESS
     */
    if (ctx->previousStage != CMD_STAGE_RECEIVE_RESPONSE ||
        ctx->rval != TSS2_RC_SUCCESS)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    ctx->nextData = (UINT8 *)ctx->rspParamsSize - ctx->cmdBuffer;

    rval = Tss2_MU_TPM2_ST_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &next, &tag);
    if (rval)
        return rval;

    /* Skiping over response params size field */
    if (tag == TPM2_ST_SESSIONS)
        rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                        ctx->maxCmdSize,
                                        &ctx->nextData,
                                        NULL);

    return rval;
}

TSS2_RC CommonOneCall(
    _TSS2_SYS_CONTEXT_BLOB *ctx,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_RC rval;

    if (ctx->rval != TSS2_RC_SUCCESS)
        return ctx->rval;

    if (cmdAuthsArray) {
        rval = Tss2_Sys_SetCmdAuths((TSS2_SYS_CONTEXT *)ctx, cmdAuthsArray);
        if (rval)
            return rval;
    }

    rval = Tss2_Sys_Execute((TSS2_SYS_CONTEXT *)ctx);
    if (rval)
        return rval;

    if (ctx->rsp_header.responseCode)
        return ctx->rsp_header.responseCode;

    if (BE_TO_HOST_16(resp_header_from_cxt(ctx)->tag) ==
            TPM2_ST_SESSIONS && rspAuthsArray)
        rval = Tss2_Sys_GetRspAuths((TSS2_SYS_CONTEXT *)ctx, rspAuthsArray);

    return rval;
}
