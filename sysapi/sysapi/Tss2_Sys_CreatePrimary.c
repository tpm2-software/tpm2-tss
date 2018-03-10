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

#include "tpm20.h"
#include "sysapi_util.h"

TSS2_RC Tss2_Sys_CreatePrimary_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY primaryHandle,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (!creationPCR)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_CreatePrimary);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(primaryHandle, ctx->cmdBuffer,
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

    rval = Tss2_MU_TPM2B_DATA_Marshal(outsideInfo, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPML_PCR_SELECTION_Marshal(creationPCR,
                                              ctx->cmdBuffer,
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

TSS2_RC Tss2_Sys_CreatePrimary_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2_HANDLE *objectHandle,
    TPM2B_PUBLIC *outPublic,
    TPM2B_CREATION_DATA *creationData,
    TPM2B_DIGEST *creationHash,
    TPMT_TK_CREATION *creationTicket,
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

    rval = Tss2_MU_TPM2B_PUBLIC_Unmarshal(ctx->cmdBuffer,
                                          ctx->maxCmdSize,
                                          &ctx->nextData, outPublic);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_CREATION_DATA_Unmarshal(ctx->cmdBuffer,
                                                 ctx->maxCmdSize,
                                                 &ctx->nextData,
                                                 creationData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_DIGEST_Unmarshal(ctx->cmdBuffer,
                                          ctx->maxCmdSize,
                                          &ctx->nextData,
                                          creationHash);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_TK_CREATION_Unmarshal(ctx->cmdBuffer,
                                              ctx->maxCmdSize,
                                              &ctx->nextData,
                                              creationTicket);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NAME_Unmarshal(ctx->cmdBuffer,
                                        ctx->maxCmdSize,
                                        &ctx->nextData, name);
    return rval;
}

TSS2_RC Tss2_Sys_CreatePrimary(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_HIERARCHY primaryHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR,
    TPM2_HANDLE *objectHandle,
    TPM2B_PUBLIC *outPublic,
    TPM2B_CREATION_DATA *creationData,
    TPM2B_DIGEST *creationHash,
    TPMT_TK_CREATION *creationTicket,
    TPM2B_NAME *name,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !creationPCR)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_CreatePrimary_Prepare(sysContext, primaryHandle, inSensitive,
                                          inPublic, outsideInfo, creationPCR);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);

    if (rval)
        return rval;

    rval = Tss2_Sys_CreatePrimary_Complete(sysContext, objectHandle, outPublic,
                                           creationData, creationHash,
                                           creationTicket, name);
    return rval;

}
