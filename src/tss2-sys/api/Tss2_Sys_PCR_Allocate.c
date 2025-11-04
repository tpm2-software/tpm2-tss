/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"      // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"      // for TSS2_RC, UINT32, TSS2_SYS_RC_BAD_REFERENCE
#include "tss2_mu.h"          // for Tss2_MU_UINT32_Unmarshal, Tss2_MU_TPML_...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPMI_RH_PLATFORM, TPMI_YES_NO, TPML_PCR...

TSS2_RC Tss2_Sys_PCR_Allocate_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM authHandle,
    const TPML_PCR_SELECTION *pcrAllocation)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !pcrAllocation)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = ValidateTPML_PCR_SELECTION(pcrAllocation);
    if (rval)
        return rval;

    rval = CommonPreparePrologue(ctx, TPM2_CC_PCR_Allocate);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(authHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPML_PCR_SELECTION_Marshal(pcrAllocation,
                                              ctx->cmdBuffer,
                                              ctx->maxCmdSize,
                                              &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_PCR_Allocate_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_YES_NO *allocationSuccess,
    UINT32 *maxPCR,
    UINT32 *sizeNeeded,
    UINT32 *sizeAvailable)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT8_Unmarshal(ctx->cmdBuffer,
                                   ctx->maxCmdSize,
                                   &ctx->nextData,
                                   allocationSuccess);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    maxPCR);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    sizeNeeded);
    if (rval)
        return rval;

    return Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    sizeAvailable);
}

TSS2_RC Tss2_Sys_PCR_Allocate(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PLATFORM authHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPML_PCR_SELECTION *pcrAllocation,
    TPMI_YES_NO *allocationSuccess,
    UINT32 *maxPCR,
    UINT32 *sizeNeeded,
    UINT32 *sizeAvailable,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!pcrAllocation)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_PCR_Allocate_Prepare(sysContext, authHandle, pcrAllocation);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_PCR_Allocate_Complete(sysContext, allocationSuccess, maxPCR,
                                          sizeNeeded, sizeAvailable);
}
