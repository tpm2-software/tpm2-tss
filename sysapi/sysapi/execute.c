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

TSS2_RC Tss2_Sys_ExecuteAsync(TSS2_SYS_CONTEXT *sysContext)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    rval = tss2_tcti_transmit(ctx->tctiContext,
                              HOST_TO_BE_32(req_header_from_cxt(ctx)->commandSize),
                              ctx->cmdBuffer);
    if (rval)
        return rval;

    ctx->previousStage = CMD_STAGE_SEND_COMMAND;

    return rval;
}

TSS2_RC Tss2_Sys_ExecuteFinish(TSS2_SYS_CONTEXT *sysContext, int32_t timeout)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;
    size_t responseSize = 0;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->previousStage != CMD_STAGE_SEND_COMMAND)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    responseSize = ctx->maxCmdSize;

    rval = tss2_tcti_receive(ctx->tctiContext, &responseSize,
                             ctx->cmdBuffer, timeout);
    if (rval)
        return rval;

    if (rval == TSS2_TCTI_RC_INSUFFICIENT_BUFFER)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    /*
     * Unmarshal the tag, response size, and response code as soon
     * as possible. Later processing code should get this data from
     * the TPM20_Header_Out in the context structure. No need to
     * unmarshal this stuff again.
     */
     ctx->nextData = 0;

     rval = Tss2_MU_TPM2_ST_Unmarshal(ctx->cmdBuffer,
                                     ctx->maxCmdSize,
                                     &ctx->nextData,
                                     &ctx->rsp_header.tag);
    if (rval)
        return rval;

     rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                     ctx->maxCmdSize,
                                     &ctx->nextData,
                                     &ctx->rsp_header.responseSize);
    if (rval)
        return rval;

    if (ctx->rsp_header.responseSize > ctx->maxCmdSize) {
        ctx->rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
        return TSS2_SYS_RC_MALFORMED_RESPONSE;
    }

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    &ctx->rsp_header.responseCode);
    if (rval)
        return rval;

    rval = ctx->rsp_header.responseCode;
    /*
     * NOTE: this is only to maintain state between API calls
     * It should be eventually removed.
     */
    ctx->rval = rval;

    /* If we received a TPM error other than CANCELED or if we didn't
     * receive enough response bytes, reset SAPI state machine to
     * CMD_STAGE_PREPARE. There's nothing else we can do for current command.
     */
    if (ctx->rsp_header.responseSize < sizeof(TPM20_Header_Out)) {
        ctx->previousStage = CMD_STAGE_PREPARE;
        return TSS2_SYS_RC_INSUFFICIENT_RESPONSE;
    }
    if (rval == TPM2_RC_CANCELED) {
        ctx->previousStage = CMD_STAGE_PREPARE;
        return TSS2_SYS_RC_INSUFFICIENT_RESPONSE;
    }

    ctx->previousStage = CMD_STAGE_RECEIVE_RESPONSE;
    return rval;
}

TSS2_RC Tss2_Sys_Execute(TSS2_SYS_CONTEXT *sysContext)
{
    TSS2_RC rval;

    if (!sysContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_ExecuteAsync(sysContext);
    if (rval)
        return rval;

    return Tss2_Sys_ExecuteFinish(sysContext, TSS2_TCTI_TIMEOUT_BLOCK);
}
