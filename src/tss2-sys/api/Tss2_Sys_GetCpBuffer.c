/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stddef.h>       // for size_t
#include <stdint.h>       // for uint8_t

#include "sysapi_util.h"  // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"  // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_SYS_RC_BAD_R...
#include "tss2_sys.h"     // for TSS2_SYS_CONTEXT, Tss2_Sys_GetCpBuffer

TSS2_RC Tss2_Sys_GetCpBuffer(
    TSS2_SYS_CONTEXT *sysContext,
    size_t *cpBufferUsedSize,
    const uint8_t **cpBuffer)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx || !cpBufferUsedSize || !cpBuffer)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->previousStage != CMD_STAGE_PREPARE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    *cpBuffer = ctx->cpBuffer;
    *cpBufferUsedSize = ctx->cpBufferUsedSize;

    return TSS2_RC_SUCCESS;
}
