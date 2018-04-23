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
#include <string.h>

#include "tss2_tpm2_types.h"
#include "../integration/context-util.h"
#include "../integration/sapi-util.h"
#include "tpmclient.int.h"

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

TSS2_RC EncryptCFB(
    SESSION *session,
    TPM2B_MAX_BUFFER *encryptedData,
    TPM2B_MAX_BUFFER *clearData,
    TPM2B_AUTH *authValue)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_MAX_BUFFER encryptKey;
    TPM2B_IV iv;

    rval = GenerateSessionEncryptDecryptKey(session, &encryptKey, &iv, authValue);
    if (rval)
        return rval;

    return encrypt_cfb(encryptedData, clearData, &encryptKey, &iv);
}

TSS2_RC DecryptCFB(
    SESSION *session,
    TPM2B_MAX_BUFFER *clearData,
    TPM2B_MAX_BUFFER *encryptedData,
    TPM2B_AUTH *authValue)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPM2B_MAX_BUFFER encryptKey;
    TPM2B_IV iv;

    rval = GenerateSessionEncryptDecryptKey(session, &encryptKey, &iv, authValue);
    if (rval)
        return rval;

    return decrypt_cfb(clearData, encryptedData, &encryptKey, &iv);
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

