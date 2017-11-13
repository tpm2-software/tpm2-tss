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
// This function does an HMAC on a null-terminated list of input buffers.
//
UINT32 TpmHmac( TPMI_ALG_HASH hashAlg, TPM2B *key, TPM2B **bufferList, TPM2B_DIGEST *result )
{
    TPM2B_AUTH nullAuth;
    TPMI_DH_OBJECT sequenceHandle;
    int i;
    TPM2B emptyBuffer;
    TPMT_TK_HASHCHECK validation;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPM2B_AUTH hmac;
    TPM2B_NONCE nonce;

    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;

    UINT32 rval;
    TPM2_HANDLE keyHandle;
    TPM2B_NAME keyName;

    TPM2B keyAuth;
    TSS2_SYS_CONTEXT *sysContext;

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    // Set result size to 0, in case any errors occur
    result->size = 0;

    keyAuth.size = 0;
    nullAuth.size = 0;

    rval = LoadExternalHMACKey( hashAlg, key, &keyHandle, &keyName );
    if( rval != TPM2_RC_SUCCESS )
    {
        return( rval );
    }

    // Init input sessions struct
    sessionData.sessionHandle = TPM2_RS_PW;
    nonce.size = 0;
    sessionData.nonce = nonce;
    CopySizedByteBuffer((TPM2B *)&hmac, (TPM2B *)&keyAuth);
    sessionData.hmac = hmac;
    *( (UINT8 *)((void *)&( sessionData.sessionAttributes ) ) ) = 0;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths = &sessionDataArray[0];

    // Init sessions out struct
    sessionsDataOut.rspAuthsCount = 1;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];

    emptyBuffer.size = 0;

    sysContext = InitSysContext( 3000, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
        return TSS2_APP_ERROR_LEVEL + TPM2_RC_FAILURE;

    rval = Tss2_Sys_HMAC_Start( sysContext, keyHandle, &sessionsData, &nullAuth, hashAlg, &sequenceHandle, 0 );

    if( rval != TPM2_RC_SUCCESS )
        goto teardown;

    hmac.size = 0;
    sessionData.hmac = hmac;
    for( i = 0; bufferList[i] != 0; i++ )
    {
        rval = Tss2_Sys_SequenceUpdate ( sysContext, sequenceHandle, &sessionsData, (TPM2B_MAX_BUFFER *)( bufferList[i] ), &sessionsDataOut );

        if( rval != TPM2_RC_SUCCESS )
            goto teardown;
    }

    INIT_SIMPLE_TPM2B_SIZE( *result );
    rval = Tss2_Sys_SequenceComplete ( sysContext, sequenceHandle, &sessionsData, ( TPM2B_MAX_BUFFER *)&emptyBuffer,
            TPM2_RH_PLATFORM, result, &validation, &sessionsDataOut );

    if( rval != TPM2_RC_SUCCESS )
        goto teardown;

    rval = Tss2_Sys_FlushContext( sysContext, keyHandle );

teardown:
    TeardownSysContext( &sysContext );
    return rval;

}
