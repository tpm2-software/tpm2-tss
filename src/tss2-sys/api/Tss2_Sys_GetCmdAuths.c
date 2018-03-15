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

#include "util/tss2_endian.h"
#include "tss2_tpm2_types.h"
#include "tss2_mu.h"
#include "sysapi_util.h"

TSS2_RC Tss2_Sys_GetRspAuths(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval = TSS2_RC_SUCCESS;
    size_t offset = 0, offset_tmp;
    int i = 0;

    if (!ctx || !rspAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->previousStage != CMD_STAGE_RECEIVE_RESPONSE ||
        ctx->rsp_header.responseCode != TSS2_RC_SUCCESS ||
        ctx->authAllowed == 0)
        return TSS2_SYS_RC_BAD_SEQUENCE;


    if (TPM2_ST_SESSIONS != ctx->rsp_header.tag)
        return rval;

    offset += sizeof(TPM20_Header_Out);
    offset += ctx->numResponseHandles * sizeof(TPM2_HANDLE);
    offset += BE_TO_HOST_32(*ctx->rspParamsSize);
    offset += sizeof(UINT32);
    offset_tmp = offset;

    /* Validate the auth area before copying it */
    for (i = 0; i < ctx->authsCount; i++) {

        if (offset_tmp > ctx->rsp_header.responseSize)
            return TSS2_SYS_RC_MALFORMED_RESPONSE;

        offset_tmp += sizeof(UINT16) +
            BE_TO_HOST_16(*(UINT16 *)(ctx->cmdBuffer + offset_tmp));

        if (offset_tmp > ctx->rsp_header.responseSize)
            return TSS2_SYS_RC_MALFORMED_RESPONSE;

        offset_tmp += 1;

        if (offset_tmp > ctx->rsp_header.responseSize)
            return TSS2_SYS_RC_MALFORMED_RESPONSE;

        offset_tmp += sizeof(UINT16) +
            BE_TO_HOST_16(*(UINT16 *)(ctx->cmdBuffer + offset_tmp));

        if (offset_tmp > ctx->rsp_header.responseSize)
            return TSS2_SYS_RC_MALFORMED_RESPONSE;

        if (i + 1 > ctx->authsCount)
            return TSS2_SYS_RC_INVALID_SESSIONS;
    }

    /* Unmarshal the auth area */
    for (i = 0; i < ctx->authsCount; i++) {
        rval = Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal(ctx->cmdBuffer,
                                            ctx->maxCmdSize,
                                            &offset, &rspAuthsArray->auths[i]);
        if (rval)
            break;
    }

    rspAuthsArray->count = ctx->authsCount;

    return rval;
}
