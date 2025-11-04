/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2020, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"      // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"      // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE, TSS...
#include "tss2_mu.h"          // for Tss2_MU_UINT32_Marshal, Tss2_MU_TPM2B_D...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPM2B_MAX_BUFFER, TPMI_DH_OBJECT, TPM2B...

TSS2_RC Tss2_Sys_CertifyX509_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT objectHandle,
    TPMI_DH_OBJECT signHandle,
    const TPM2B_DATA *reserved,
    const TPMT_SIG_SCHEME *inScheme,
    const TPM2B_MAX_BUFFER *partialCertificate)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !reserved || !inScheme || !partialCertificate)
        return TSS2_SYS_RC_BAD_REFERENCE;

	/* reserved has to be an empty buffer */
    if (reserved->size > 0)
        return TSS2_SYS_RC_BAD_VALUE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_CertifyX509);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(objectHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(signHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_DATA_Marshal(reserved, ctx->cmdBuffer,
                                      ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_SIG_SCHEME_Marshal(inScheme, ctx->cmdBuffer,
                                           ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_MAX_BUFFER_Marshal(partialCertificate, ctx->cmdBuffer,
                                            ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_CertifyX509_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_BUFFER *addedToCertificate,
    TPM2B_DIGEST *tbsDigest,
    TPMT_SIGNATURE *signature)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_MAX_BUFFER_Unmarshal(ctx->cmdBuffer,
                                              ctx->maxCmdSize,
                                              &ctx->nextData,
                                              addedToCertificate);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_DIGEST_Unmarshal(ctx->cmdBuffer,
                                          ctx->maxCmdSize,
                                          &ctx->nextData,
                                          tbsDigest);
    if (rval)
        return rval;

    return Tss2_MU_TPMT_SIGNATURE_Unmarshal(ctx->cmdBuffer,
                                            ctx->maxCmdSize,
                                            &ctx->nextData,
                                            signature);
}

TSS2_RC Tss2_Sys_CertifyX509(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT objectHandle,
    TPMI_DH_OBJECT signHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPM2B_DATA *reserved,
    const TPMT_SIG_SCHEME *inScheme,
    const TPM2B_MAX_BUFFER *partialCertificate,
    TPM2B_MAX_BUFFER *addedToCertificate,
    TPM2B_DIGEST *tbsDigest,
    TPMT_SIGNATURE *signature,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_CertifyX509_Prepare(sysContext, objectHandle, signHandle,
                                        reserved, inScheme, partialCertificate);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_CertifyX509_Complete(sysContext, addedToCertificate,
                                         tbsDigest, signature);
}
