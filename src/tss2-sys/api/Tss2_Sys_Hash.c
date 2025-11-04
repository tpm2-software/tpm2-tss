/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"      // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"      // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE, TSS...
#include "tss2_mu.h"          // for Tss2_MU_UINT16_Marshal, Tss2_MU_TPM2B_D...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPM2B_DIGEST, TPM2B_MAX_BUFFER, TPMI_AL...

TSS2_RC Tss2_Sys_Hash_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPM2B_MAX_BUFFER *data,
    TPMI_ALG_HASH hashAlg,
    TPMI_RH_HIERARCHY hierarchy)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (IsAlgorithmWeak(hashAlg, 0))
        return TSS2_SYS_RC_BAD_VALUE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_Hash);
    if (rval)
        return rval;

    if (!data) {
        ctx->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    } else {

        rval = Tss2_MU_TPM2B_MAX_BUFFER_Marshal(data, ctx->cmdBuffer,
                                                ctx->maxCmdSize,
                                                &ctx->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_UINT16_Marshal(hashAlg, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(hierarchy, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_Hash_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_DIGEST *outHash,
    TPMT_TK_HASHCHECK *validation)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_DIGEST_Unmarshal(ctx->cmdBuffer,
                                          ctx->maxCmdSize,
                                          &ctx->nextData,
                                          outHash);
    if (rval)
        return rval;

    return Tss2_MU_TPMT_TK_HASHCHECK_Unmarshal(ctx->cmdBuffer,
                                               ctx->maxCmdSize,
                                               &ctx->nextData,
                                               validation);
}

TSS2_RC Tss2_Sys_Hash(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPM2B_MAX_BUFFER *data,
    TPMI_ALG_HASH hashAlg,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST *outHash,
    TPMT_TK_HASHCHECK *validation,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_Hash_Prepare(sysContext, data, hashAlg, hierarchy);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_Hash_Complete(sysContext, outHash, validation);
}
