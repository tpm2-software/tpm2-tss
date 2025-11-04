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
#include "tss2_mu.h"          // for Tss2_MU_TPMT_HA_Unmarshal, Tss2_MU_TPM2...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPMT_HA, TPM2B_MAX_BUFFER, TPM2_CC_Fiel...

TSS2_RC Tss2_Sys_FieldUpgradeData_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2B_MAX_BUFFER const *fuData)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_FieldUpgradeData);
    if (rval)
        return rval;

    if (!fuData) {
        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);

    } else {

        rval = Tss2_MU_TPM2B_MAX_BUFFER_Marshal(fuData,
                                                ctx->cmdBuffer,
                                                ctx->maxCmdSize,
                                                &ctx->nextData);
    }

    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_FieldUpgradeData_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMT_HA *nextDigest,
    TPMT_HA *firstDigest)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_HA_Unmarshal(ctx->cmdBuffer,
                                     ctx->maxCmdSize,
                                     &ctx->nextData,
                                     nextDigest);
    if (rval)
        return rval;

    return Tss2_MU_TPMT_HA_Unmarshal(ctx->cmdBuffer,
                                     ctx->maxCmdSize,
                                     &ctx->nextData,
                                     firstDigest);
}

TSS2_RC Tss2_Sys_FieldUpgradeData(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    TPM2B_MAX_BUFFER const *fuData,
    TPMT_HA *nextDigest,
    TPMT_HA *firstDigest,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_FieldUpgradeData_Prepare(sysContext, fuData);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_FieldUpgradeData_Complete(sysContext, nextDigest,
                                              firstDigest);
}
