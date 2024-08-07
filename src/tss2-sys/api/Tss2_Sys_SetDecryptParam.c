/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h>            // for uint8_t
#include <string.h>            // for memmove, size_t

#include "sysapi_util.h"       // for _TSS2_SYS_CONTEXT_BLOB, req_header_fro...
#include "tss2_common.h"       // for UINT8, TSS2_SYS_RC_INSUFFICIENT_CONTEXT
#include "tss2_sys.h"          // for Tss2_Sys_GetDecryptParam, TSS2_SYS_CON...
#include "util/tss2_endian.h"  // for BE_TO_HOST_32, HOST_TO_BE_16, HOST_TO_...

TSS2_RC Tss2_Sys_SetDecryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t param_size,
    const uint8_t *param_buffer)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    size_t curr_param_size;
    const uint8_t *curr_param_buffer;
    UINT32 command_size;
    const UINT8 *src, *limit;
    UINT8 *dst;
    UINT32 len;
    TSS2_RC rval;

    if (!param_buffer || !ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    if (ctx->decryptAllowed == 0)
        return TSS2_SYS_RC_NO_DECRYPT_PARAM;

    if (param_size < 1)
        return TSS2_SYS_RC_BAD_VALUE;

    if (BE_TO_HOST_32(req_header_from_cxt(ctx)->commandSize) +
        param_size > ctx->maxCmdSize)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    rval = Tss2_Sys_GetDecryptParam(sysContext, &curr_param_size,
                                    &curr_param_buffer);
    if (rval)
        return rval;

    if (curr_param_size == 0 && ctx->decryptNull) {

        /* Move the current cpBuffer down to make room for the decrypt param */
        src = ctx->cpBuffer + 2;
        dst = ctx->cpBuffer + ctx->cpBufferUsedSize + 2;
        len = ctx->cpBufferUsedSize - 2;
        limit = ctx->cmdBuffer + ctx->maxCmdSize;

        if (dst + len > limit)
            return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

        memmove(dst, src, len);

        ctx->cpBufferUsedSize += param_size;
        *(UINT16 *)ctx->cpBuffer = HOST_TO_BE_16(param_size);

        /* Fixup the command size */
        command_size = BE_TO_HOST_32(req_header_from_cxt(ctx)->commandSize);
        command_size += param_size;
        req_header_from_cxt(ctx)->commandSize = HOST_TO_BE_32(command_size);
    } else if (curr_param_size != param_size) {
        return TSS2_SYS_RC_BAD_SIZE;
    }

    /* Copy the encrypted param into the command buffer */
    src = param_buffer;
    dst = (UINT8 *)curr_param_buffer;
    len = param_size;
    limit = ctx->cmdBuffer + ctx->maxCmdSize;

    *(UINT16 *)ctx->cpBuffer = HOST_TO_BE_16(param_size);

    if (dst + len > limit)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    memmove(dst, src, len);
    return rval;
}
