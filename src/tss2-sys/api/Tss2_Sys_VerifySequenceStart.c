/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2026, Cisco Systems, Inc.
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"     // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"     // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE
#include "tss2_mu.h"         // for Tss2_MU_*
#include "tss2_sys.h"        // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h" // for TPM2B_SIGNATURE_CTX, TPM2B_AUTH, TPMI_DH_OBJECT

TSS2_RC
Tss2_Sys_VerifySequenceStart_Prepare(TSS2_SYS_CONTEXT           *sysContext,
                                     TPMI_DH_OBJECT              keyHandle,
                                     const TPM2B_AUTH           *auth,
                                     const TPM2B_SIGNATURE_HINT *hint,
                                     const TPM2B_SIGNATURE_CTX  *context) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx || !context)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_VerifySequenceStart);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    if (!auth) {
        ctx->decryptNull = 1;
        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    } else {
        rval = Tss2_MU_TPM2B_AUTH_Marshal(auth, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    }

    if (rval)
        return rval;

    if (!hint) {
        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    } else {
        rval = Tss2_MU_TPM2B_SIGNATURE_HINT_Marshal(hint, ctx->cmdBuffer, ctx->maxCmdSize,
                                                    &ctx->nextData);
    }

    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal(context, ctx->cmdBuffer, ctx->maxCmdSize,
                                               &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_VerifySequenceStart_Complete(TSS2_SYS_CONTEXT *sysContext,
                                      TPMI_DH_OBJECT   *sequenceHandle) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    return Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData,
                                    sequenceHandle);
}

TSS2_RC
Tss2_Sys_VerifySequenceStart(TSS2_SYS_CONTEXT             *sysContext,
                             TPMI_DH_OBJECT                keyHandle,
                             TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                             const TPM2B_AUTH             *auth,
                             const TPM2B_SIGNATURE_HINT   *hint,
                             const TPM2B_SIGNATURE_CTX    *context,
                             TPMI_DH_OBJECT               *sequenceHandle,
                             TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!context)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_VerifySequenceStart_Prepare(sysContext, keyHandle, auth, hint, context);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_VerifySequenceStart_Complete(sysContext, sequenceHandle);
}
