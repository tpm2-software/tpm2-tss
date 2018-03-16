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

#include <inttypes.h>

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"

#include "sysapi_util.h"
#define LOGMODULE sys
#include "util/log.h"

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

    if (TSS2_TCTI_TRANSMIT (tctiContext) == NULL || TSS2_TCTI_RECEIVE (tctiContext) == NULL)
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
                  TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_LEVEL);
        return TSS2_SYS_RC_ABI_MISMATCH;
    }

    ctx->tctiContext = tctiContext;
    InitSysContextPtrs(ctx, contextSize);
    InitSysContextFields(ctx);
    ctx->previousStage = CMD_STAGE_INITIALIZE;

    return TSS2_RC_SUCCESS;
}
