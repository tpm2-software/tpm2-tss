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

#include "tpm20.h"
#include "sample.h"
#include <string.h>

TSS2_RC GetBlockSizeInBits( TPMI_ALG_SYM algorithm, UINT32 *blockSizeInBits )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( algorithm == TPM2_ALG_AES )
        *blockSizeInBits = 128;
    else if( algorithm == TPM2_ALG_SM3_256 )
        *blockSizeInBits = 128;
    else
        rval = TSS2_APP_RC_BAD_ALGORITHM;

    return rval;
}

TSS2_RC
GenerateSessionEncryptDecryptKey (
    SESSION              *session,
    TPM2B_MAX_BUFFER     *cfbKey,
    TPM2B_IV             *ivIn,
    TPM2B_AUTH           *authValue)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT32 blockSize = 0;
    TPM2B_MAX_BUFFER key, sessionValue;

    if (ivIn == NULL || cfbKey == NULL) {
        return APPLICATION_ERROR( TSS2_BASE_RC_INSUFFICIENT_BUFFER );
    }
    rval = GetBlockSizeInBits (session->symmetric.algorithm, &blockSize);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }

    INIT_SIMPLE_TPM2B_SIZE(key);
    CopySizedByteBuffer((TPM2B *)&sessionValue, (TPM2B *)&session->sessionKey);
    CatSizedByteBuffer((TPM2B *)&sessionValue, (TPM2B *)authValue);

    rval = KDFa (session->authHash,
                 (TPM2B *)&sessionValue,
                 "CFB",
                 (TPM2B *)&session->nonceNewer,
                 (TPM2B *)&session->nonceOlder,
                 session->symmetric.keyBits.sym + blockSize,
                 &key);
    if (rval != TSS2_RC_SUCCESS) {
        return rval;
    }

    if (key.size != (session->symmetric.keyBits.sym + blockSize) / 8) {
        return APPLICATION_ERROR (TSS2_BASE_RC_INSUFFICIENT_BUFFER);
    }

    ivIn->size = blockSize / 8;
    cfbKey->size = (session->symmetric.keyBits.sym) / 8;
    if (ivIn->size > sizeof (ivIn->buffer) ||
        (cfbKey->size + ivIn->size) > TPM2_MAX_DIGEST_BUFFER) {
        return APPLICATION_ERROR (TSS2_BASE_RC_INSUFFICIENT_BUFFER);
    }
    memcpy (ivIn->buffer, &key.buffer[cfbKey->size], ivIn->size);
    memcpy (cfbKey->buffer, key.buffer, cfbKey->size);
    return rval;
}

UINT32 LoadSessionEncryptDecryptKey( TPMT_SYM_DEF *symmetric, TPM2B_MAX_BUFFER *key, TPM2_HANDLE *keyHandle, TPM2B_NAME *keyName )
{
    TPM2B keyAuth = { 0 };
    TPM2B_SENSITIVE inPrivate;
    TPM2B_PUBLIC inPublic;
    UINT32 rval;
    TSS2_SYS_CONTEXT *sysContext;

    inPrivate.sensitiveArea.sensitiveType = TPM2_ALG_SYMCIPHER;
    inPrivate.size = CopySizedByteBuffer((TPM2B *)&inPrivate.sensitiveArea.authValue, (TPM2B *)&keyAuth);
    inPrivate.sensitiveArea.seedValue.size = 0;
    inPrivate.size += CopySizedByteBuffer((TPM2B *)&inPrivate.sensitiveArea.sensitive.bits, (TPM2B *)key);
    inPrivate.size += 2 * sizeof( UINT16 );

    inPublic.publicArea.type = TPM2_ALG_SYMCIPHER;
    inPublic.publicArea.nameAlg = TPM2_ALG_NULL;
    *( UINT32 *)&( inPublic.publicArea.objectAttributes )= 0;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.symDetail.sym.algorithm = symmetric->algorithm;
    inPublic.publicArea.parameters.symDetail.sym.keyBits = symmetric->keyBits;
    inPublic.publicArea.parameters.symDetail.sym.mode = symmetric->mode;
    inPublic.publicArea.unique.sym.size = 0;

    sysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
    {
        return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;
    }

    INIT_SIMPLE_TPM2B_SIZE( *keyName );
    rval = Tss2_Sys_LoadExternal( sysContext, 0, &inPrivate, &inPublic, TPM2_RH_NULL, keyHandle, keyName, 0 );

    TeardownSysContext( &sysContext );

    return rval;
}

TSS2_RC EncryptCFB( SESSION *session, TPM2B_MAX_BUFFER *encryptedData, TPM2B_MAX_BUFFER *clearData, TPM2B_AUTH *authValue )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_MAX_BUFFER encryptKey;
    TPM2B_IV ivIn, ivOut;
    TPM2_HANDLE keyHandle;
    TPM2B_NAME keyName;
    TSS2_SYS_CONTEXT *sysContext;

    // Authorization array for command (only has one auth structure).
    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .count = 1,
        .auths = { 0 }};

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
            sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
            sessionsData.auths[0].nonce.size = 0;
            sessionsData.auths[0].sessionAttributes = 0;
            sessionsData.auths[0].hmac.size = 0;
            encryptedData->size = sizeof( *encryptedData ) - 1;
            INIT_SIMPLE_TPM2B_SIZE( ivOut );
            rval = Tss2_Sys_EncryptDecrypt( sysContext, keyHandle, &sessionsData, NO, TPM2_ALG_CFB, &ivIn,
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
    TPM2_HANDLE keyHandle;
    TPM2B_NAME keyName;
    TSS2_SYS_CONTEXT *sysContext;
   // Authorization array for command (only has one auth structure).
     TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .count = 1,
        .auths = { 0 }};

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
            sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
            sessionsData.auths[0].nonce.size = 0;
            sessionsData.auths[0].sessionAttributes = 0;
            sessionsData.auths[0].hmac.size = 0;

            INIT_SIMPLE_TPM2B_SIZE( ivOut );
            rval = Tss2_Sys_EncryptDecrypt( sysContext, keyHandle, &sessionsData, YES, TPM2_ALG_CFB, &ivIn,
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

    CopySizedByteBuffer((TPM2B *)&key, (TPM2B *)&session->sessionKey);
    CatSizedByteBuffer((TPM2B *)&key, (TPM2B *)authValue);

    rval = KDFa(session->authHash, (TPM2B *)&key, "XOR", (TPM2B *)&session->nonceNewer,
                (TPM2B *)&session->nonceOlder, inputData->size * 8, &mask);
    if( rval == TSS2_RC_SUCCESS )
    {
        for( i = 0; i < inputData->size; i++ )
        {
            outputData->buffer[i] = inputData->buffer[i] ^ mask.buffer[i];
        }
        outputData->size = inputData->size;
    }

    return rval;
}


TSS2_RC EncryptCommandParam( SESSION *session, TPM2B_MAX_BUFFER *encryptedData, TPM2B_MAX_BUFFER *clearData, TPM2B_AUTH *authValue )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( session->symmetric.algorithm == TPM2_ALG_AES )
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

    if( session->symmetric.algorithm == TPM2_ALG_AES )
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

