/***********************************************************************;
 * Copyright (c) 2018, Intel Corporation
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

TSS2_RC Tss2_Sys_CreateLoaded_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY parentHandle,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (!inPublic)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_CreateLoaded);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(parentHandle, ctx->cmdBuffer,
                          ctx->maxCmdSize,
                          &ctx->nextData);
    if (rval)
        return rval;

    if (!inSensitive) {
        ctx->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    } else {
        rval = Tss2_MU_TPM2B_SENSITIVE_CREATE_Marshal(inSensitive,
                                                      ctx->cmdBuffer,
                                                      ctx->maxCmdSize,
                                                      &ctx->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_PUBLIC_Marshal(inPublic, ctx->cmdBuffer,
                                        ctx->maxCmdSize,
                                        &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;

    rval = CommonPrepareEpilogue(ctx);
    return rval;
}

TSS2_RC Tss2_Sys_CreateLoaded_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2_HANDLE *objectHandle,
    TPM2B_PRIVATE *outPrivate,
    TPM2B_PUBLIC *outPublic,
    TPM2B_NAME *name)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData, objectHandle);
    if (rval)
        return rval;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_PRIVATE_Unmarshal(ctx->cmdBuffer,
                                           ctx->maxCmdSize,
                                           &ctx->nextData, outPrivate);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_PUBLIC_Unmarshal(ctx->cmdBuffer,
                                          ctx->maxCmdSize,
                                          &ctx->nextData, outPublic);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NAME_Unmarshal(ctx->cmdBuffer,
                                        ctx->maxCmdSize,
                                        &ctx->nextData, name);
    return rval;
}

TSS2_RC Tss2_Sys_CreateLoaded(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY parentHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    TPM2_HANDLE *objectHandle,
    TPM2B_PRIVATE *outPrivate,
    TPM2B_PUBLIC *outPublic,
    TPM2B_NAME *name,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !objectHandle || !outPrivate || !outPublic || !name)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_CreateLoaded_Prepare(sysContext, parentHandle,
                                          inSensitive, inPublic);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);

    if (rval)
        return rval;

    rval = Tss2_Sys_CreateLoaded_Complete(sysContext, objectHandle, outPrivate,
                                           outPublic, name);
    return rval;
}
