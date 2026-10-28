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
#include "tss2_mu.h"         // for Tss2_MU_UINT32_Marshal, Tss2_MU_TPM2B_*
#include "tss2_sys.h"        // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h" // for TPM2B_SHARED_SECRET, TPM2B_KEM_CIPHERTEXT, TPMI_DH_OBJECT

TSS2_RC
Tss2_Sys_Decapsulate_Prepare(TSS2_SYS_CONTEXT           *sysContext,
                             TPMI_DH_OBJECT              keyHandle,
                             const TPM2B_KEM_CIPHERTEXT *ciphertext) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx || !ciphertext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_Decapsulate);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPM2B_KEM_CIPHERTEXT_Marshal(ciphertext, ctx->cmdBuffer, ctx->maxCmdSize,
                                                &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;
    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_Decapsulate_Complete(TSS2_SYS_CONTEXT *sysContext, TPM2B_SHARED_SECRET *sharedSecret) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    return Tss2_MU_TPM2B_SHARED_SECRET_Unmarshal(ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData,
                                                 sharedSecret);
}

TSS2_RC
Tss2_Sys_Decapsulate(TSS2_SYS_CONTEXT             *sysContext,
                     TPMI_DH_OBJECT                keyHandle,
                     TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                     const TPM2B_KEM_CIPHERTEXT   *ciphertext,
                     TPM2B_SHARED_SECRET          *sharedSecret,
                     TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ciphertext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_Decapsulate_Prepare(sysContext, keyHandle, ciphertext);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_Decapsulate_Complete(sysContext, sharedSecret);
}
