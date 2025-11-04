/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"      // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"      // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE
#include "tss2_mu.h"          // for Tss2_MU_TPM2B_ECC_POINT_Unmarshal, Tss2...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPM2B_ECC_POINT, TPMI_DH_OBJECT, TPM2_C...

TSS2_RC Tss2_Sys_ECDH_KeyGen_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT keyHandle)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_ECDH_KeyGen);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_ECDH_KeyGen_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_ECC_POINT *zPoint,
    TPM2B_ECC_POINT *pubPoint)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_ECC_POINT_Unmarshal(ctx->cmdBuffer,
                                             ctx->maxCmdSize,
                                             &ctx->nextData,
                                             zPoint);
    if (rval)
        return rval;

    return Tss2_MU_TPM2B_ECC_POINT_Unmarshal(ctx->cmdBuffer,
                                             ctx->maxCmdSize,
                                             &ctx->nextData,
                                             pubPoint);
}

TSS2_RC Tss2_Sys_ECDH_KeyGen(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_OBJECT keyHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    TPM2B_ECC_POINT *zPoint,
    TPM2B_ECC_POINT *pubPoint,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_ECDH_KeyGen_Prepare(sysContext, keyHandle);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_ECDH_KeyGen_Complete(sysContext, zPoint, pubPoint);
}
