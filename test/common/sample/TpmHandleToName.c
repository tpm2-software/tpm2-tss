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
#include "sample.h"
#include "sysapi_util.h"

//
//
UINT32 TpmHandleToName( TPM_HANDLE handle, TPM2B_NAME *name )
{
    TPM_RC rval;
    TPM2B_NAME qualifiedName;
    TPM2B_PUBLIC public;
    TPM2B_NV_PUBLIC nvPublic;
    TSS2_SYS_CONTEXT *sysContext;
    UINT8 *namePtr = &( name->t.name[0] );

    // Initialize name to zero length in case of failure.
    INIT_SIMPLE_TPM2B_SIZE( *name );
    INIT_SIMPLE_TPM2B_SIZE( qualifiedName );

    if( handle == ( TPM_HT_NO_HANDLE ) )
    {
        name->b.size = 0;
        rval = TPM_RC_SUCCESS;
    }
    else
    {
        switch( handle >> HR_SHIFT )
        {
            case TPM_HT_NV_INDEX:
                sysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
                if( sysContext == 0 )
                    return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;

                nvPublic.t.size = 0;
                rval = Tss2_Sys_NV_ReadPublic( sysContext, handle, 0, &nvPublic, name, 0 );
                TeardownSysContext( &sysContext );
                break;

            case TPM_HT_TRANSIENT:
            case TPM_HT_PERSISTENT:
                sysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
                if( sysContext == 0 )
                    return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;

                public.t.size = 0;
				rval = Tss2_Sys_ReadPublic( sysContext, handle, 0, &public, name, &qualifiedName, 0 );
                TeardownSysContext( &sysContext );
                break;

            default:
                rval = TPM_RC_SUCCESS;
                name->b.size = sizeof( TPM_HANDLE );
                *(TPM_HANDLE *)namePtr = CHANGE_ENDIAN_DWORD( handle );
        }
    }
    return rval;
}
