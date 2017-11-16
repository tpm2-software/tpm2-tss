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

TSS2_RC Tss2_Sys_MakeCredential_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT handle,
    const TPM2B_DIGEST *credential,
    const TPM2B_NAME *objectName)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_MakeCredential);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(handle, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    if (!credential) {
        ctx->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    } else {

        rval = Tss2_MU_TPM2B_DIGEST_Marshal(credential, ctx->cmdBuffer,
                                            ctx->maxCmdSize,
                                            &ctx->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NAME_Marshal(objectName, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_MakeCredential_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ID_OBJECT *credentialBlob,
    TPM2B_ENCRYPTED_SECRET *secret)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(ctx->cmdBuffer,
                                             ctx->maxCmdSize,
                                             &ctx->nextData,
                                             credentialBlob);
    if (rval)
        return rval;

    return Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(ctx->cmdBuffer,
                                                    ctx->maxCmdSize,
                                                    &ctx->nextData,
                                                    secret);
}

TSS2_RC Tss2_Sys_MakeCredential(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT handle,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    const TPM2B_DIGEST *credential,
    const TPM2B_NAME *objectName,
    TPM2B_ID_OBJECT *credentialBlob,
    TPM2B_ENCRYPTED_SECRET *secret,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_MakeCredential_Prepare(sysContext, handle, credential, objectName);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_MakeCredential_Complete(sysContext, credentialBlob, secret);
}
