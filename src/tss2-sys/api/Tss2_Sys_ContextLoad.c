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
#include "tss2_mu.h"          // for Tss2_MU_TPMS_CONTEXT_Marshal, Tss2_MU_U...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, Tss2_Sys_ContextLoad
#include "tss2_tpm2_types.h"  // for TPMI_DH_CONTEXT, TPMS_CONTEXT, TPM2_CC_...

TSS2_RC Tss2_Sys_ContextLoad_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPMS_CONTEXT *context)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !context)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_ContextLoad);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMS_CONTEXT_Marshal(context, ctx->cmdBuffer,
                                        ctx->maxCmdSize,
                                        &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 0;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_ContextLoad_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT *loadedHandle)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    loadedHandle);
    if (rval)
        return rval;

    return CommonComplete(ctx);
}

TSS2_RC Tss2_Sys_ContextLoad(
    TSS2_SYS_CONTEXT *sysContext,
    const TPMS_CONTEXT *context,
    TPMI_DH_CONTEXT *loadedHandle)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!context)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_ContextLoad_Prepare(sysContext, context);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, 0, 0);
    if (rval)
        return rval;

    return Tss2_Sys_ContextLoad_Complete(sysContext, loadedHandle);
}
