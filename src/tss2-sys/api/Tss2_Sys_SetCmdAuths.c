/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2015 - 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h>            // for uint16_t
#include <string.h>            // for memmove, memset, size_t

#include "sysapi_util.h"       // for _TSS2_SYS_CONTEXT_BLOB, req_header_fro...
#include "tss2_common.h"       // for UINT32, UINT8, TSS2_RC, TSS2_SYS_RC_IN...
#include "tss2_mu.h"           // for Tss2_MU_TPMS_AUTH_COMMAND_Marshal, Tss...
#include "tss2_sys.h"          // for TSS2L_SYS_AUTH_COMMAND, TSS2_SYS_CONTEXT
#include "tss2_tpm2_types.h"   // for TPMS_AUTH_COMMAND, TPM2B_AUTH, TPM2B_N...
#include "util/tss2_endian.h"  // for BE_TO_HOST_32, HOST_TO_BE_16, HOST_TO_...

TSS2_RC Tss2_Sys_SetCmdAuths(
    TSS2_SYS_CONTEXT *sysContext,
    const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    uint16_t i;
    UINT32 authSize = 0;
    UINT32 newCmdSize = 0;
    size_t authOffset;
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if (!ctx || !cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (cmdAuthsArray->count > TSS2_SYS_MAX_SESSIONS ||
        cmdAuthsArray->count == 0)
        return TSS2_SYS_RC_BAD_SIZE;

    if (ctx->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    if (!ctx->authAllowed)
        return rval;

    ctx->authsCount = 0;

    req_header_from_cxt(ctx)->tag = HOST_TO_BE_16(TPM2_ST_SESSIONS);

    /* Calculate size needed for authorization area, check for any null
     * pointers, and check for decrypt/encrypt sessions. */
    for (i = 0; i < cmdAuthsArray->count; i++) {
        authSize += sizeof(TPMI_SH_AUTH_SESSION);
        authSize += sizeof(UINT16) + cmdAuthsArray->auths[i].nonce.size;
        authSize += sizeof(UINT8);
        authSize += sizeof(UINT16) + cmdAuthsArray->auths[i].hmac.size;
    }

    newCmdSize = authSize;
    newCmdSize += sizeof(UINT32); /* authorization size field */
    newCmdSize += BE_TO_HOST_32(req_header_from_cxt(ctx)->commandSize);

    if (newCmdSize > ctx->maxCmdSize)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    if (ctx->cpBufferUsedSize > ctx->maxCmdSize)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    /* We're going to have to move stuff around.
     * First move current cpBuffer down by the auth area size. */
    memmove(ctx->cpBuffer + authSize + sizeof(UINT32),
            ctx->cpBuffer, ctx->cpBufferUsedSize);

    /* Reset the auth size field */
    memset(ctx->cpBuffer, 0, sizeof(UINT32));

    /* Now copy in the authorization area. */
    authOffset = ctx->cpBuffer - ctx->cmdBuffer;
    rval = Tss2_MU_UINT32_Marshal(authSize, ctx->cmdBuffer,
                          newCmdSize, &authOffset);
    if (rval)
        return rval;

    for (i = 0; i < cmdAuthsArray->count; i++) {
        rval = Tss2_MU_TPMS_AUTH_COMMAND_Marshal(&cmdAuthsArray->auths[i],
                                         ctx->cmdBuffer, newCmdSize,
                                         &authOffset);
        if (rval)
            break;
    }

    ctx->cpBuffer += authSize + sizeof(UINT32);

    /* Now update the command size. */
    req_header_from_cxt(ctx)->commandSize = HOST_TO_BE_32(newCmdSize);
    ctx->authsCount = cmdAuthsArray->count;
    return rval;
}
