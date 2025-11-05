/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2025, Juergen Repp
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h" // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h" // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE, UINT16
#include "tss2_sys.h"    // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND

TSS2_RC
Tss2_Sys_Abort(TSS2_SYS_CONTEXT *sysContext) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    ctx->previousStage = CMD_STAGE_INITIALIZE;
    return TSS2_RC_SUCCESS;
}
