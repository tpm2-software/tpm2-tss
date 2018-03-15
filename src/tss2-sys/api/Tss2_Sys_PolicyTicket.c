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

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"
#include "sysapi_util.h"

TSS2_RC Tss2_Sys_PolicyTicket_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY policySession,
    const TPM2B_TIMEOUT *timeout,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *authName,
    const TPMT_TK_AUTH *ticket)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !ticket)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_PolicyTicket);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(policySession, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    if (!timeout) {
        ctx->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    } else {

        rval = Tss2_MU_TPM2B_TIMEOUT_Marshal(timeout, ctx->cmdBuffer,
                                             ctx->maxCmdSize,
                                             &ctx->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_DIGEST_Marshal(cpHashA, ctx->cmdBuffer,
                                        ctx->maxCmdSize,
                                        &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NONCE_Marshal(policyRef, ctx->cmdBuffer,
                                       ctx->maxCmdSize,
                                       &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_NAME_Marshal(authName, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_TK_AUTH_Marshal(ticket, ctx->cmdBuffer,
                                        ctx->maxCmdSize,
                                        &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_PolicyTicket_Complete (
    TSS2_SYS_CONTEXT *sysContext)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    return CommonComplete(ctx);
}

TSS2_RC Tss2_Sys_PolicyTicket(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY policySession,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPM2B_TIMEOUT *timeout,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *authName,
    const TPMT_TK_AUTH *ticket,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ticket)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_PolicyTicket_Prepare(sysContext, policySession, timeout,
                                         cpHashA, policyRef, authName, ticket);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_PolicyTicket_Complete(sysContext);
}
