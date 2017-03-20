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
#include <string.h>

TSS2_RC GetBlockSizeInBits( TPMI_ALG_SYM algorithm, UINT32 *blockSizeInBits )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( algorithm == TPM_ALG_AES )
        *blockSizeInBits = 128;
    else if( algorithm == TPM_ALG_SM3_256 )
        *blockSizeInBits = 128;
    else
        rval = TSS2_APP_RC_BAD_ALGORITHM;

    return rval;
}

TSS2_RC GenerateSessionEncryptDecryptKey( SESSION *session, TPM2B_MAX_BUFFER *cfbKey, TPM2B_IV *ivIn, TPM2B_AUTH *authValue )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT32 blockSize;
    TPM2B_MAX_BUFFER key, sessionValue;

    rval = GetBlockSizeInBits( session->symmetric.algorithm, &blockSize );

    CopySizedByteBuffer( &sessionValue.b, &session->sessionKey.b );
    CatSizedByteBuffer( &sessionValue.b, &authValue->b );

    if( rval == TSS2_RC_SUCCESS )
    {
        INIT_SIMPLE_TPM2B_SIZE( key );
        rval = KDFa( session->authHash, &( sessionValue.b ), "CFB", &( session->nonceNewer.b ),
                &( session->nonceOlder.b ), session->symmetric.keyBits.sym + blockSize, &key );
        if( rval == TSS2_RC_SUCCESS )
        {
            if( key.t.size == ( session->symmetric.keyBits.sym + blockSize ) / 8 )
            {
                if( ivIn != 0 && cfbKey != 0 )
                {
                    ivIn->t.size = blockSize / 8;
                    cfbKey->t.size = (session->symmetric.keyBits.sym) / 8;

                    if( ( ivIn->t.size <= sizeof( ivIn->t.buffer ) ) &&
                            ( ( cfbKey->t.size + ivIn->t.size ) <= MAX_DIGEST_BUFFER ) &&
                        ( cfbKey->t.size <= MAX_DIGEST_BUFFER ) )
                    {

                        memcpy( (void *)&ivIn->t.buffer[0],
                                (void *)&( key.t.buffer[ cfbKey->t.size ] ),
                                ivIn->t.size );

                        memcpy( (void *)&cfbKey->t.buffer[0], (void *)&key.t.buffer[0],
                                cfbKey->t.size );
                    }
                    else
                    {
                        rval = APPLICATION_ERROR( TSS2_BASE_RC_INSUFFICIENT_BUFFER );
                    }
                }
                else
                {
                    rval = APPLICATION_ERROR( TSS2_BASE_RC_INSUFFICIENT_BUFFER );
                }
            }
        }
    }

    return rval;
}

UINT32 LoadSessionEncryptDecryptKey( TPMT_SYM_DEF *symmetric, TPM2B_MAX_BUFFER *key, TPM_HANDLE *keyHandle, TPM2B_NAME *keyName )
{
    TPM2B keyAuth = { 0 };
    TPM2B_SENSITIVE inPrivate;
    TPM2B_PUBLIC inPublic;
    UINT32 rval;
    TSS2_SYS_CONTEXT *sysContext;

    inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_SYMCIPHER;
    inPrivate.t.size = CopySizedByteBuffer( &(inPrivate.t.sensitiveArea.authValue.b), &keyAuth);
    inPrivate.t.sensitiveArea.seedValue.b.size = 0;
    inPrivate.t.size += CopySizedByteBuffer( &inPrivate.t.sensitiveArea.sensitive.bits.b, &key->b );
    inPrivate.t.size += 2 * sizeof( UINT16 );

    inPublic.t.publicArea.type = TPM_ALG_SYMCIPHER;
    inPublic.t.publicArea.nameAlg = TPM_ALG_NULL;
    *( UINT32 *)&( inPublic.t.publicArea.objectAttributes )= 0;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.sign = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.authPolicy.t.size = 0;
    inPublic.t.publicArea.parameters.symDetail.sym.algorithm = symmetric->algorithm;
    inPublic.t.publicArea.parameters.symDetail.sym.keyBits = symmetric->keyBits;
    inPublic.t.publicArea.parameters.symDetail.sym.mode = symmetric->mode;
    inPublic.t.publicArea.unique.sym.t.size = 0;

    sysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
    {
        return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;
    }

    INIT_SIMPLE_TPM2B_SIZE( *keyName );
    rval = Tss2_Sys_LoadExternal( sysContext, 0, &inPrivate, &inPublic, TPM_RH_NULL, keyHandle, keyName, 0 );

    TeardownSysContext( &sysContext );

    return rval;
}

TSS2_RC EncryptCFB( SESSION *session, TPM2B_MAX_BUFFER *encryptedData, TPM2B_MAX_BUFFER *clearData, TPM2B_AUTH *authValue )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_MAX_BUFFER encryptKey;
    TPM2B_IV ivIn, ivOut;
    TPM_HANDLE keyHandle;
    TPM2B_NAME keyName;
    TSS2_SYS_CONTEXT *sysContext;

    // Authorization structure for command.
    TPMS_AUTH_COMMAND sessionData;

    // Create and init authorization area for command:
    // only 1 authorization area.
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };

    // Authorization array for command (only has one auth structure).
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };

    sysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
    {
        TeardownSysContext( &sysContext );
        return TSS2_APP_RC_TEARDOWN_SYS_CONTEXT_FAILED;
    }

    rval = GenerateSessionEncryptDecryptKey( session, &encryptKey, &ivIn, authValue );

    if( rval == TSS2_RC_SUCCESS )
    {
        rval = LoadSessionEncryptDecryptKey( &session->symmetric, &encryptKey, &keyHandle, &keyName );
        if( rval == TSS2_RC_SUCCESS )
        {
            // Encrypt the data.
            sessionData.sessionHandle = TPM_RS_PW;
            sessionData.nonce.t.size = 0;
            *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;
            sessionData.hmac.t.size = 0;
            encryptedData->t.size = sizeof( *encryptedData ) - 1;
            INIT_SIMPLE_TPM2B_SIZE( ivOut );
            rval = Tss2_Sys_EncryptDecrypt( sysContext, keyHandle, &sessionsData, NO, TPM_ALG_CFB, &ivIn,
                    clearData, encryptedData, &ivOut, 0 );
            if( rval == TSS2_RC_SUCCESS )
            {
                rval = Tss2_Sys_FlushContext( sysContext, keyHandle );
            }
        }
    }
    TeardownSysContext( &sysContext );

    return rval;
}

TSS2_RC DecryptCFB( SESSION *session, TPM2B_MAX_BUFFER *clearData, TPM2B_MAX_BUFFER *encryptedData, TPM2B_AUTH *authValue )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_MAX_BUFFER encryptKey;
    TPM2B_IV ivIn, ivOut;
    TPM_HANDLE keyHandle;
    TPM2B_NAME keyName;
    TSS2_SYS_CONTEXT *sysContext;

    // Authorization structure for command.
    TPMS_AUTH_COMMAND sessionData;

    // Create and init authorization area for command:
    // only 1 authorization area.
    TPMS_AUTH_COMMAND *sessionDataArray[1] = { &sessionData };

    // Authorization array for command (only has one auth structure).
    TSS2_SYS_CMD_AUTHS sessionsData = { 1, &sessionDataArray[0] };


    sysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
    {
        TeardownSysContext( &sysContext );
        return TSS2_APP_RC_TEARDOWN_SYS_CONTEXT_FAILED;
    }

    rval = GenerateSessionEncryptDecryptKey( session, &encryptKey, &ivIn, authValue );

    if( rval == TSS2_RC_SUCCESS )
    {
        rval = LoadSessionEncryptDecryptKey( &session->symmetric, &encryptKey, &keyHandle, &keyName );
        if( rval == TSS2_RC_SUCCESS )
        {
            // Decrypt the data.
            sessionData.sessionHandle = TPM_RS_PW;
            sessionData.nonce.t.size = 0;
            *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;
            sessionData.hmac.t.size = 0;

            INIT_SIMPLE_TPM2B_SIZE( ivOut );
            rval = Tss2_Sys_EncryptDecrypt( sysContext, keyHandle, &sessionsData, YES, TPM_ALG_CFB, &ivIn,
                    encryptedData, clearData, &ivOut, 0 );
            if( rval == TSS2_RC_SUCCESS )
            {
                rval = Tss2_Sys_FlushContext( sysContext, keyHandle );
            }
        }
    }
    TeardownSysContext( &sysContext );

    return rval;
}


TSS2_RC EncryptDecryptXOR( SESSION *session, TPM2B_MAX_BUFFER *outputData, TPM2B_MAX_BUFFER *inputData, TPM2B_AUTH *authValue )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_MAX_BUFFER key, mask;
    int i;

    CopySizedByteBuffer( &key.b, &session->sessionKey.b );
    CatSizedByteBuffer( &key.b, &authValue->b );

    rval = KDFa( session->authHash, &key.b, "XOR", &session->nonceNewer.b, &session->nonceOlder.b, inputData->t.size * 8, &mask );
    if( rval == TSS2_RC_SUCCESS )
    {
        for( i = 0; i < inputData->t.size; i++ )
        {
            outputData->t.buffer[i] = inputData->t.buffer[i] ^ mask.t.buffer[i];
        }
        outputData->t.size = inputData->t.size;
    }

    return rval;
}


TSS2_RC EncryptCommandParam( SESSION *session, TPM2B_MAX_BUFFER *encryptedData, TPM2B_MAX_BUFFER *clearData, TPM2B_AUTH *authValue )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( session->symmetric.algorithm == TPM_ALG_AES )
    {
        // CFB mode encryption.
        rval = EncryptCFB( session, encryptedData, clearData, authValue );
    }
    else
    {
        // XOR mode encryption.
        rval = EncryptDecryptXOR( session, encryptedData, clearData, authValue );
    }

    return rval;
}

TSS2_RC DecryptResponseParam( SESSION *session, TPM2B_MAX_BUFFER *clearData, TPM2B_MAX_BUFFER *encryptedData, TPM2B_AUTH *authValue )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( session->symmetric.algorithm == TPM_ALG_AES )
    {
        // CFB mode decryption.
        rval = DecryptCFB( session, clearData, encryptedData, authValue );
    }
    else
    {
        // XOR mode decryption.
        rval = EncryptDecryptXOR( session, clearData, encryptedData, authValue );
    }

    return rval;
}

