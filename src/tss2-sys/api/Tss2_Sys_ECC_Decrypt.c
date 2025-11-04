/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2025 - 2025, Huawei Technologies Co., Ltd.
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"      // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"      // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE
#include "tss2_mu.h"          // for Tss2_MU_UINT16_Marshal, Tss2_MU_TPM2B_D...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPM2B_ECC_POINT, TPM2B_DATA, TPMI_...

TSS2_RC Tss2_Sys_ECC_Decrypt_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT keyHandle,
    const TPM2B_ECC_POINT *c1,
    const TPM2B_MAX_BUFFER *c2,
    const TPM2B_DIGEST *c3,
    const TPMT_KDF_SCHEME *inScheme)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !inScheme)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_ECC_Decrypt);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, ctx->cmdBuffer,
                            ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    if (c1) {
        rval = Tss2_MU_TPM2B_ECC_POINT_Marshal(c1, ctx->cmdBuffer,
                                    ctx->maxCmdSize, &ctx->nextData);
    } else {
        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer, ctx->maxCmdSize,
                                    &ctx->nextData);
    }
    if (rval) {
        return rval;
    }

    if (c2) {
        rval = Tss2_MU_TPM2B_MAX_BUFFER_Marshal(c2, ctx->cmdBuffer,
                                    ctx->maxCmdSize, &ctx->nextData);
    } else {
        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer, ctx->maxCmdSize,
                                    &ctx->nextData);
    }
    if (rval) {
        return rval;
    }

    if (c3) {
        rval = Tss2_MU_TPM2B_DIGEST_Marshal(c3, ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData);
    } else {
        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer, ctx->maxCmdSize,
                                    &ctx->nextData);
    }
    if (rval) {
        return rval;
    }

    rval = Tss2_MU_TPMT_KDF_SCHEME_Marshal(inScheme, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;
    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_ECC_Decrypt_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_BUFFER *plaintText)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    return Tss2_MU_TPM2B_MAX_BUFFER_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize, &ctx->nextData, plaintText);
}

TSS2_RC Tss2_Sys_ECC_Decrypt(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT keyHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPM2B_ECC_POINT *c1,
    const TPM2B_MAX_BUFFER *c2,
    const TPM2B_DIGEST *c3,
    const TPMT_KDF_SCHEME *inScheme,
    TPM2B_MAX_BUFFER *plaintText,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!inScheme)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_ECC_Decrypt_Prepare(sysContext, keyHandle, c1, c2, c3,
                                        inScheme);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_ECC_Decrypt_Complete(sysContext, plaintText);
}
