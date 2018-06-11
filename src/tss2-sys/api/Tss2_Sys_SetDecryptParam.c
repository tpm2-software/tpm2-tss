/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/
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

    if (ctx->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    if (ctx->decryptAllowed == 0)
        return TSS2_SYS_RC_NO_DECRYPT_PARAM;

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
