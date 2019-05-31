/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015-2018, Intel Corporation
 *
 * Copyright 2015, Andreas Fuchs @ Fraunhofer SIT
 *
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"

#include "sysapi_util.h"
#define LOGMODULE sys
#include "util/log.h"

#define TSSWG_INTEROP 1
#define TSS_SAPI_FIRST_FAMILY 2
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 108

TSS2_RC Tss2_Sys_Initialize(
    TSS2_SYS_CONTEXT *sysContext,
    size_t contextSize,
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_ABI_VERSION *abiVersion)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx || !tctiContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (contextSize < sizeof(_TSS2_SYS_CONTEXT_BLOB))
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    if (!TSS2_TCTI_TRANSMIT (tctiContext) ||
        !TSS2_TCTI_RECEIVE (tctiContext))
        return TSS2_SYS_RC_BAD_TCTI_STRUCTURE;

    /* Checks for ABI negotiation. */
    if (abiVersion != NULL &&
        (abiVersion->tssCreator != TSSWG_INTEROP ||
         abiVersion->tssFamily != TSS_SAPI_FIRST_FAMILY ||
         abiVersion->tssLevel != TSS_SAPI_FIRST_LEVEL ||
         abiVersion->tssVersion != TSS_SAPI_FIRST_VERSION)) {
        LOG_ERROR("ABI-Version of application %" PRIx32 ".%" PRIu32 ".%"
                  PRIu32 ".%" PRIu32 " differs from ABI version of SAPI %"
                  PRIx32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32,
                  abiVersion->tssCreator, abiVersion->tssFamily,
                  abiVersion->tssLevel, abiVersion->tssVersion,
                  TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY,
                  TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION);
        return TSS2_SYS_RC_ABI_MISMATCH;
    }

    ctx->tctiContext = tctiContext;
    InitSysContextPtrs(ctx, contextSize);
    InitSysContextFields(ctx);
    ctx->previousStage = CMD_STAGE_INITIALIZE;

    return TSS2_RC_SUCCESS;
}
