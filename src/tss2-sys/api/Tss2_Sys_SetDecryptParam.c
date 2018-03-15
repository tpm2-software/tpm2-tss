//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
#include <string.h>

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"
#include "sysapi_util.h"
#include "util/tss2_endian.h"

TSS2_RC Tss2_Sys_SetDecryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t decryptParamSize,
    const uint8_t *decryptParamBuffer)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    size_t currDecryptParamSize;
    const uint8_t *currDecryptParamBuffer;
    TSS2_RC rval;
    UINT32 currCommandSize;
    const UINT8 *src, *limit;
    UINT8 *dst;
    UINT32 len;

    if (!decryptParamBuffer || !ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (BE_TO_HOST_32(req_header_from_cxt(ctx)->commandSize) +
        decryptParamSize > ctx->maxCmdSize)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    rval = Tss2_Sys_GetDecryptParam(sysContext, &currDecryptParamSize,
                                    &currDecryptParamBuffer);
    if (rval)
        return rval;

    if (currDecryptParamSize == 0 && ctx->decryptNull)
    {
        if (decryptParamSize < 1)
            return TSS2_SYS_RC_BAD_VALUE;

        /* Move stuff around. First move current cpBuffer down. */
        src = ctx->cpBuffer + 2;
        dst = ctx->cpBuffer + ctx->cpBufferUsedSize + 2;
        len = ctx->cpBufferUsedSize - 2;
        limit = ctx->cmdBuffer + ctx->maxCmdSize;

        if (dst + len > limit)
            return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

        memmove(dst, src, len);

        ctx->cpBufferUsedSize += decryptParamSize;
        *(UINT16 *)ctx->cpBuffer = HOST_TO_BE_16(decryptParamSize);

        src = decryptParamBuffer;
        dst = (UINT8 *) currDecryptParamBuffer;
        len = decryptParamSize;
        limit = ctx->cmdBuffer + ctx->maxCmdSize;

        if (dst + len > limit)
            return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

        /* Now copy in the encrypted decrypt param. */
        memmove(dst, src, len);

        /* And fixup the command size. */
        currCommandSize = BE_TO_HOST_32(req_header_from_cxt(ctx)->commandSize);
        currCommandSize += decryptParamSize;
        req_header_from_cxt(ctx)->commandSize = HOST_TO_BE_32(currCommandSize);
    }
    else
    {
        if (decryptParamSize != currDecryptParamSize)
            return TSS2_SYS_RC_BAD_SIZE;

        *(UINT16 *)ctx->cpBuffer = HOST_TO_BE_16(decryptParamSize);

        src = decryptParamBuffer;
        dst = (UINT8 *) currDecryptParamBuffer;
        len = decryptParamSize;
        limit = ctx->cmdBuffer + ctx->maxCmdSize;

        if (dst + len > limit)
            return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

        memmove(dst, src, len);
    }

    return rval;
}
