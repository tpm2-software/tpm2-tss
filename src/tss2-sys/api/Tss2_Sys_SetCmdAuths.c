/***********************************************************************
 * Copyright (c) 2015 - 2018, Intel Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ***********************************************************************/
#include <string.h>

#include "util/tss2_endian.h"
#include "tss2_tpm2_types.h"
#include "tss2_mu.h"
#include "sysapi_util.h"

TSS2_RC Tss2_Sys_SetCmdAuths(
    TSS2_SYS_CONTEXT *sysContext,
    const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    uint8_t i;
    UINT32 authSize = 0;
    UINT32 newCmdSize = 0;
    size_t authOffset;
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if (!ctx || !cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (cmdAuthsArray->count > TPM2_MAX_SESSION_NUM)
        return TSS2_SYS_RC_BAD_VALUE;

    if (ctx->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    if (!ctx->authAllowed)
        return rval;

    ctx->authsCount = 0;

    if (!cmdAuthsArray->count)
        return rval;

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
    *(UINT32 *)ctx->cpBuffer = 0;

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
