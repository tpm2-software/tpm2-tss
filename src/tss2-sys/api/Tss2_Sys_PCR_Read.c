/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"      // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"      // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE, UINT32
#include "tss2_mu.h"          // for Tss2_MU_TPML_DIGEST_Unmarshal, Tss2_MU_...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPML_PCR_SELECTION, TPML_DIGEST, TPM2_C...

TSS2_RC Tss2_Sys_PCR_Read_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    const TPML_PCR_SELECTION *pcrSelectionIn)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx || !pcrSelectionIn)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_PCR_Read);
    if (rval)
        return rval;

    rval = Tss2_MU_TPML_PCR_SELECTION_Marshal(pcrSelectionIn,
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

TSS2_RC Tss2_Sys_PCR_Read_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    UINT32 *pcrUpdateCounter,
    TPML_PCR_SELECTION *pcrSelectionOut,
    TPML_DIGEST *pcrValues)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer,
                                    ctx->maxCmdSize,
                                    &ctx->nextData,
                                    pcrUpdateCounter);
    if (rval)
        return rval;

    rval = Tss2_MU_TPML_PCR_SELECTION_Unmarshal(ctx->cmdBuffer,
                                                ctx->maxCmdSize,
                                                &ctx->nextData,
                                                pcrSelectionOut);
    if (rval)
        return rval;

    return Tss2_MU_TPML_DIGEST_Unmarshal(ctx->cmdBuffer,
                                         ctx->maxCmdSize,
                                         &ctx->nextData, pcrValues);
}

TSS2_RC Tss2_Sys_PCR_Read(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    const TPML_PCR_SELECTION *pcrSelectionIn,
    UINT32 *pcrUpdateCounter,
    TPML_PCR_SELECTION *pcrSelectionOut,
    TPML_DIGEST *pcrValues,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!pcrSelectionIn)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_PCR_Read_Prepare(sysContext, pcrSelectionIn);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_PCR_Read_Complete(sysContext, pcrUpdateCounter,
                                      pcrSelectionOut, pcrValues);
}
