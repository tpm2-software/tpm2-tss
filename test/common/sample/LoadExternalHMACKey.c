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

#include <tpm20.h>   
#include <tss2_sysapi_util.h>
#include <sample.h>


UINT32 LoadExternalHMACKey( TPMI_ALG_HASH hashAlg, TPM2B *key, TPM_HANDLE *keyHandle, TPM2B_NAME *keyName )
{
    TPM2B keyAuth;
    TPM2B_SENSITIVE inPrivate;
    TPM2B_PUBLIC inPublic;
    UINT32 rval;
    TSS2_SYS_CONTEXT *sysContext;
    
    keyAuth.size = 0;

    inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_KEYEDHASH;
    inPrivate.t.size = CopySizedByteBuffer( &(inPrivate.t.sensitiveArea.authValue.b), &keyAuth);
    inPrivate.t.sensitiveArea.seedValue.b.size = 0;
    inPrivate.t.size += CopySizedByteBuffer( &inPrivate.t.sensitiveArea.sensitive.bits.b, key);
    inPrivate.t.size += 2 * sizeof( UINT16 );

    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.nameAlg = TPM_ALG_NULL;
    *( UINT32 *)&( inPublic.t.publicArea.objectAttributes )= 0;
    inPublic.t.publicArea.objectAttributes.sign = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.authPolicy.t.size = 0;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg;
    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    sysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
    {
        TeardownSysContext( &sysContext );
        return TSS2_APP_ERROR_LEVEL + TPM_RC_FAILURE;
    }
    
    rval = Tss2_Sys_LoadExternal( sysContext, 0, &inPrivate, &inPublic, TPM_RH_NULL, keyHandle, keyName, 0 );

    TeardownSysContext( &sysContext );
    
    return rval;
}
