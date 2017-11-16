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

TSS2_RC Tss2_Sys_StartAuthSession_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT tpmKey,
    TPMI_DH_ENTITY bind,
    const TPM2B_NONCE *nonceCaller,
    const TPM2B_ENCRYPTED_SECRET *encryptedSalt,
    TPM2_SE sessionType,
    const TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH authHash)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !symmetric)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_StartAuthSession);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(tpmKey, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(bind, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    if (!nonceCaller) {
        ctx->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    } else {

        rval = Tss2_MU_TPM2B_NONCE_Marshal(nonceCaller, ctx->cmdBuffer,
                                           ctx->maxCmdSize,
                                           &ctx->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Marshal(encryptedSalt,
                                                  ctx->cmdBuffer,
                                                  ctx->maxCmdSize,
                                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT8_Marshal(sessionType, ctx->cmdBuffer,
                                 ctx->maxCmdSize,
                                 &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_SYM_DEF_Marshal(symmetric, ctx->cmdBuffer,
                                        ctx->maxCmdSize,
                                        &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT16_Marshal(authHash, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_StartAuthSession_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_AUTH_SESSION *sessionHandle,
    TPM2B_NONCE *nonceTPM)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    sessionHandle);
    if (rval)
        return rval;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    return Tss2_MU_TPM2B_NONCE_Unmarshal(ctx->cmdBuffer,
                                         ctx->maxCmdSize,
                                         &ctx->nextData, nonceTPM);
}

TSS2_RC Tss2_Sys_StartAuthSession(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT tpmKey,
    TPMI_DH_ENTITY bind,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_NONCE *nonceCaller,
    const TPM2B_ENCRYPTED_SECRET *encryptedSalt,
    TPM2_SE sessionType,
    const TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH authHash,
    TPMI_SH_AUTH_SESSION *sessionHandle,
    TPM2B_NONCE *nonceTPM,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!symmetric)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_StartAuthSession_Prepare(sysContext, tpmKey, bind, nonceCaller, encryptedSalt, sessionType, symmetric, authHash);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_StartAuthSession_Complete(sysContext, sessionHandle, nonceTPM);
}
