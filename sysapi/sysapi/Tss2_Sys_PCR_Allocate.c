/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
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

#include "sapi/tpm20.h"
#include "sysapi_util.h"

TSS2_RC Tss2_Sys_PCR_Allocate_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM authHandle,
    const TPML_PCR_SELECTION *pcrAllocation)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !pcrAllocation)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_PCR_Allocate);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(authHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPML_PCR_SELECTION_Marshal(pcrAllocation,
                                              ctx->cmdBuffer,
                                              ctx->maxCmdSize,
                                              &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_PCR_Allocate_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_YES_NO *allocationSuccess,
    UINT32 *maxPCR,
    UINT32 *sizeNeeded,
    UINT32 *sizeAvailable)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT8_Unmarshal(ctx->cmdBuffer,
                                   ctx->maxCmdSize,
                                   &ctx->nextData,
                                   allocationSuccess);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    maxPCR);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    sizeNeeded);
    if (rval)
        return rval;

    return Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    sizeAvailable);
}

TSS2_RC Tss2_Sys_PCR_Allocate(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM authHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPML_PCR_SELECTION *pcrAllocation,
    TPMI_YES_NO *allocationSuccess,
    UINT32 *maxPCR,
    UINT32 *sizeNeeded,
    UINT32 *sizeAvailable,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!pcrAllocation)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_PCR_Allocate_Prepare(sysContext, authHandle, pcrAllocation);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_PCR_Allocate_Complete(sysContext, allocationSuccess, maxPCR,
                                          sizeNeeded, sizeAvailable);
}
