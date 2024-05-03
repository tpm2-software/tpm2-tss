/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h>       // for uint8_t
#include <string.h>       // for memmove, size_t

#include "sysapi_util.h"  // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"  // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_SYS_RC_BAD_R...
#include "tss2_sys.h"     // for Tss2_Sys_GetEncryptParam, TSS2_SYS_CONTEXT

TSS2_RC Tss2_Sys_SetEncryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t encryptParamSize,
    const uint8_t *encryptParamBuffer)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    size_t currEncryptParamSize;
    const uint8_t *currEncryptParamBuffer;
    TSS2_RC rval;

    if (!encryptParamBuffer || !ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_GetEncryptParam(sysContext,
                                    &currEncryptParamSize,
                                    &currEncryptParamBuffer);
    if (rval)
        return rval;

    if (encryptParamSize != currEncryptParamSize)
        return TSS2_SYS_RC_BAD_SIZE;

    if (currEncryptParamBuffer + encryptParamSize >
            ctx->cmdBuffer + ctx->maxCmdSize)
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    memmove((void *)currEncryptParamBuffer,
            encryptParamBuffer, encryptParamSize);

    return TSS2_RC_SUCCESS;
}
