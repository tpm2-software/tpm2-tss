/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"      // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"      // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE, UINT32
#include "tss2_mu.h"          // for Tss2_MU_UINT32_Marshal, Tss2_MU_TPM2_HA...
#include "tss2_sys.h"         // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h"  // for TPMI_RH_AC, TPMI_YES_NO, TPML_AC_CAPABI...

TSS2_RC Tss2_Sys_AC_GetCapability_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_AC ac,
    TPM_AT capability,
    UINT32 count)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_AC_GetCapability);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2_HANDLE_Marshal(ac, ctx->cmdBuffer,
                                       ctx->maxCmdSize,
                                       &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(capability, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(count, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC Tss2_Sys_AC_GetCapability_Complete(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_YES_NO *moreData,
    TPML_AC_CAPABILITIES *capabilityData)
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
                                   moreData);
    if (rval)
        return rval;

    return Tss2_MU_TPML_AC_CAPABILITIES_Unmarshal(ctx->cmdBuffer,
                                                  ctx->maxCmdSize,
                                                  &ctx->nextData,
                                                  capabilityData);
}

TSS2_RC Tss2_Sys_AC_GetCapability(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_AC ac,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    TPM_AT capability,
    UINT32 count,
    TPMI_YES_NO *moreData,
    TPML_AC_CAPABILITIES *capabilityData,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_AC_GetCapability_Prepare(sysContext, ac, capability, count);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_AC_GetCapability_Complete(sysContext, moreData,
                                              capabilityData);
}
