/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <string.h>            // for memcpy

#include "sysapi_util.h"       // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"       // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_SYS_RC_...
#include "tss2_sys.h"          // for TSS2_SYS_CONTEXT, Tss2_Sys_GetCommandCode
#include "tss2_tpm2_types.h"   // for TPM2_CC
#include "util/tss2_endian.h"  // for HOST_TO_BE_32

TSS2_RC Tss2_Sys_GetCommandCode(
    TSS2_SYS_CONTEXT *sysContext,
    UINT8 *commandCode)
{
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx || !commandCode)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (ctx->previousStage == CMD_STAGE_INITIALIZE)
        return TSS2_SYS_RC_BAD_SEQUENCE;

    TPM2_CC tmp = HOST_TO_BE_32(ctx->commandCode);
    memcpy(commandCode, (void *)&tmp, sizeof(tmp));

    return TSS2_RC_SUCCESS;
}
