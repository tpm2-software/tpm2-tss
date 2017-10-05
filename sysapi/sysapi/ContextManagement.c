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

#include "sapi/tpm20.h"
#include "sysapi_util.h"

size_t Tss2_Sys_GetContextSize(size_t maxCommandSize)
{
    if( maxCommandSize == 0 )
    {
        return( sizeof( _TSS2_SYS_CONTEXT_BLOB ) + MAX_COMMAND_SIZE );
    }
    else
    {
        return( sizeof( _TSS2_SYS_CONTEXT_BLOB ) +
                ( ( maxCommandSize > sizeof( TPM20_Header_In ) ) ? maxCommandSize : ( sizeof( TPM20_Header_In )  ) ) );
    }
};

TSS2_RC Tss2_Sys_Initialize(
    TSS2_SYS_CONTEXT *sysContext,
    size_t contextSize,
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_ABI_VERSION *abiVersion
    )
{

    if( sysContext == NULL || tctiContext == NULL || abiVersion == NULL )
    {
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    if( contextSize < sizeof( _TSS2_SYS_CONTEXT_BLOB ) )
    {
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;
    }

    if (TCTI_CONTEXT_INTEL->transmit == NULL || TCTI_CONTEXT_INTEL->receive == NULL)
    {
        return TSS2_SYS_RC_BAD_TCTI_STRUCTURE;
    }

    // Checks for ABI negotiation.
    if( abiVersion->tssCreator != TSSWG_INTEROP ||
        abiVersion->tssFamily != TSS_SAPI_FIRST_FAMILY ||
        abiVersion->tssLevel != TSS_SAPI_FIRST_LEVEL ||
        abiVersion->tssVersion != TSS_SAPI_FIRST_LEVEL )
    {
        return TSS2_SYS_RC_ABI_MISMATCH;
    }

    SYS_CONTEXT->tctiContext = (TSS2_TCTI_CONTEXT *)tctiContext;
    InitSysContextPtrs( sysContext, contextSize );
    InitSysContextFields( sysContext );
    SYS_CONTEXT->previousStage = CMD_STAGE_INITIALIZE;

    return TSS2_RC_SUCCESS;
}

