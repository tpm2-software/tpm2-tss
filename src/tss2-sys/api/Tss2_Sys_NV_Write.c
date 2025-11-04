/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"      // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"      // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE, UINT16
#include "tss2_mu.h"          // for Tss2_MU_UINT16_Marshal, Tss2_MU_UINT32_...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPM2B_MAX_NV_BUFFER, TPMI_RH_NV_AUTH

TSS2_RC Tss2_Sys_NV_Write_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH authHandle,
    TPMI_RH_NV_INDEX nvIndex,
    const TPM2B_MAX_NV_BUFFER *data,
    UINT16 offset)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_NV_Write);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(authHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(nvIndex, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    if (!data) {
        ctx->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer,
                                      ctx->maxCmdSize,
                                      &ctx->nextData);
    } else {
        rval = Tss2_MU_TPM2B_MAX_NV_BUFFER_Marshal(data, ctx->cmdBuffer,
                                                   ctx->maxCmdSize,
                                                   &ctx->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_UINT16_Marshal(offset, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_NV_Write_Complete (
    TSS2_SYS_CONTEXT *sysContext)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    return CommonComplete(ctx);
}

TSS2_RC Tss2_Sys_NV_Write(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_NV_AUTH authHandle,
    TPMI_RH_NV_INDEX nvIndex,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPM2B_MAX_NV_BUFFER *data,
    UINT16 offset,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_NV_Write_Prepare(sysContext, authHandle, nvIndex, data, offset);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_NV_Write_Complete(sysContext);
}
