/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"  // for syscontext_cast, _TSS2_SYS_CONTEXT_BLOB
#include "tss2_common.h"  // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_SYS_RC_BAD_R...
#include "tss2_sys.h"     // for TSS2_SYS_CONTEXT, Tss2_Sys_GetTctiContext
#include "tss2_tcti.h"    // for TSS2_TCTI_CONTEXT

TSS2_RC Tss2_Sys_GetTctiContext(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_TCTI_CONTEXT **tctiContext)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx || !tctiContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    *tctiContext = ctx->tctiContext;

    return TSS2_RC_SUCCESS;
}
