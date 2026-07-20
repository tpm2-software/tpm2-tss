/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <string.h>

#include "sysapi_util.h"   // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_sys.h"      // for TSS2_SYS_CONTEXT, Tss2_Sys_Finalize
#include "util/aux_util.h" // for UNUSED, secure_mem_zero
void
Tss2_Sys_Finalize(TSS2_SYS_CONTEXT *sysContext) {

    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (ctx && ctx->cmdBuffer) {
        secure_mem_zero(ctx->cmdBuffer, ctx->maxCmdSize);
    }
}
