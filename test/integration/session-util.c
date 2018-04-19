/*
 * Copyright (c) 2018, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>

#include "session-util.h"
#include "sapi-util.h"
#include "context-util.h"
#include "util/tss2_endian.h"
#define LOGMODULE test
#include "util/log.h"

static SESSION *sessions = NULL;

SESSION *
get_session(TPMI_SH_AUTH_SESSION hndl)
{
    SESSION *s;

    HASH_FIND_INT(sessions, &hndl, s);
    return s;
}

static TSS2_RC
StartAuthSession(
    SESSION *session,
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_RC rval;
    TPM2B_ENCRYPTED_SECRET key;
    char label[] = "ATH";
    TSS2_SYS_CONTEXT *tmpSysContext;
    UINT16 bytes;

    key.size = 0;

    tmpSysContext = sapi_init_from_tcti_ctx(tctiContext);
    if (tmpSysContext == NULL)
        return TSS2_SYS_RC_GENERAL_FAILURE;

    if (session->nonceOlder.size == 0)
        session->nonceOlder.size = GetDigestSize(session->authHash);

    memset(session->nonceOlder.buffer, '\0', session->nonceOlder.size);
    session->nonceNewer.size = session->nonceOlder.size;
    session->nonceTpmDecrypt.size = 0;
    session->nonceTpmEncrypt.size = 0;

    rval = Tss2_Sys_StartAuthSession(
            tmpSysContext, session->tpmKey, session->bind, 0,
            &session->nonceOlder, &session->encryptedSalt,
            session->sessionType, &session->symmetric,
            session->authHash, &session->sessionHandle,
            &session->nonceNewer, 0);
    if (rval != TPM2_RC_SUCCESS)
        goto out;

    if (session->tpmKey == TPM2_RH_NULL)
        session->salt.size = 0;

    if (session->bind == TPM2_RH_NULL)
        session->authValueBind.size = 0;

    session->sessionKey.size = 0;
    if (session->tpmKey == TPM2_RH_NULL && session->bind == TPM2_RH_NULL)
        goto out;

    /* Generate the key used as input to the KDF. */
    rval = ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&key,
            (TPM2B *)&session->authValueBind);
    if (rval != TPM2_RC_SUCCESS) {
        Tss2_Sys_FlushContext(tmpSysContext, session->sessionHandle);
        goto out;
    }

    rval = ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&key,
            (TPM2B *)&session->salt);
    if (rval != TPM2_RC_SUCCESS) {
        Tss2_Sys_FlushContext(tmpSysContext, session->sessionHandle);
        goto out;
    }

    bytes = GetDigestSize(session->authHash) * 8;

    rval = KDFa(session->authHash, (TPM2B *)&key, label,
                (TPM2B *)&session->nonceNewer,
                (TPM2B *)&session->nonceOlder,
                bytes, (TPM2B_MAX_BUFFER *)&session->sessionKey);
out:
    sapi_teardown(tmpSysContext);
    return rval;
}

static TSS2_RC
TpmComputeSessionHmac(
    TSS2_SYS_CONTEXT *sysContext,
    SESSION *session,
    TPMS_AUTH_COMMAND *pSessionDataIn,
    bool command,
    TPM2_HANDLE handle1,
    TPM2_HANDLE handle2,
    TPM2_HANDLE handle3,
    TPM2B_MAX_BUFFER *hmacKey)
{
    TPM2B_DIGEST *bufferList[7];
    TPM2B_DIGEST pHash = TPM2B_DIGEST_INIT;
    TPM2B sessionAttributesByteBuffer = {
        .size = 1,
        .buffer = pSessionDataIn->sessionAttributes
    };
    UINT16 i;
    TSS2_RC rval;
    TPM2_CC cmdCode;

    rval = TpmCalcPHash(sysContext, handle1, handle2, handle3,
                        session->authHash, command, &pHash);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    rval = Tss2_Sys_GetCommandCode(sysContext, (UINT8 *)&cmdCode);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    /* cmdCode comes back as BigEndian; not suited for comparisons below. */
    cmdCode = BE_TO_HOST_32(cmdCode);
    LOGBLOB_DEBUG(hmacKey->buffer, hmacKey->size, "hmacKey=");

    i = 0;
    bufferList[i++] = (TPM2B_DIGEST *)&pHash;
    bufferList[i++] = (TPM2B_DIGEST *)&session->nonceNewer;
    bufferList[i++] = (TPM2B_DIGEST *)&session->nonceOlder;
    bufferList[i++] = (TPM2B_DIGEST *)&session->nonceTpmDecrypt;
    bufferList[i++] = (TPM2B_DIGEST *)&session->nonceTpmEncrypt;
    bufferList[i++] = (TPM2B_DIGEST *)&sessionAttributesByteBuffer;
    bufferList[i++] = 0;

    for (int j = 0; bufferList[j] != 0; j++) {
            LOGBLOB_DEBUG(&bufferList[j]->buffer[0],
                    bufferList[j]->size, "bufferlist[%d]:", j);
            ;
    }

    rval = hmac(session->authHash, hmacKey->buffer,
            hmacKey->size, bufferList,
            (TPM2B_DIGEST *)&pSessionDataIn->hmac);

    if (rval != TPM2_RC_SUCCESS) {
        LOGBLOB_ERROR(pSessionDataIn->hmac.buffer,
                      pSessionDataIn->hmac.size,
                      "HMAC Failed rval = %d !!!", rval);
        return rval;
    }
    return rval;
}

TSS2_RC ComputeCommandHmacs(
        TSS2_SYS_CONTEXT *sysContext,
        TPM2_HANDLE handle1,
        TPM2_HANDLE handle2,
        TPM2_HANDLE handle3,
        TSS2L_SYS_AUTH_COMMAND *pSessionsDataIn)
{
    TPM2_HANDLE handles[3] = {handle1, handle2, handle3};
    ENTITY *entity;
    SESSION *session;
    TPM2B_MAX_BUFFER hmac_key;
    TSS2_RC rval = TPM2_RC_SUCCESS;
    unsigned int i;
    unsigned int count = pSessionsDataIn->count;

    if (count > 3) {
        LOG_ERROR("Bad value for session count: %" PRIu16, count);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    for (i = 0; i < count; i++) {
        if (handles[i] == TPM2_RH_NULL)
            break;

        entity = GetEntity(handles[i]);
        if (!entity)
            return TSS2_SYS_RC_GENERAL_FAILURE;

        session = get_session(pSessionsDataIn->auths[i].sessionHandle);
        if (!session)
            return TPM2_RC_SUCCESS;

        CopySizedByteBuffer((TPM2B *)&hmac_key, (TPM2B *)&session->sessionKey);

        if (handles[i] != session->bind || handles[i] == TPM2_RH_NULL)
            ConcatSizedByteBuffer(&hmac_key, (TPM2B *)&entity->entityAuth);

        rval = TpmComputeSessionHmac(sysContext,
                session,
                &pSessionsDataIn->auths[i],
                true,
                handle1,
                handle2,
                handle3,
                &hmac_key);
        if (rval != TPM2_RC_SUCCESS)
            break;
    }
    return rval;
}

TSS2_RC CheckResponseHMACs(
        TSS2_SYS_CONTEXT *sysContext,
        TSS2L_SYS_AUTH_COMMAND *pSessionsDataIn,
        TPM2_HANDLE handle1,
        TPM2_HANDLE handle2,
        TPM2_HANDLE handle3,
        TSS2L_SYS_AUTH_RESPONSE *pSessionsDataOut)
{
    TPM2_HANDLE handles[3] = {handle1, handle2, handle3};
    ENTITY *entity;
    SESSION *session;
    TPM2B_MAX_BUFFER hmac_key;
    TSS2_RC rval = TPM2_RC_SUCCESS;
    unsigned int i;
    unsigned int count = pSessionsDataIn->count;

    if (count > 3) {
        LOG_ERROR("Bad value for session count: %" PRIu16, count);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    for (i = 0; i < count; i++) {
        if (handles[i] == TPM2_RH_NULL)
            break;

        entity = GetEntity(handles[i]);
        if (!entity)
            return TSS2_SYS_RC_GENERAL_FAILURE;

        session = get_session(pSessionsDataIn->auths[i].sessionHandle);
        if (!session)
            return TPM2_RC_SUCCESS;

        CopySizedByteBuffer((TPM2B *)&hmac_key, (TPM2B *)&session->sessionKey);

        if (handles[i] != session->bind)
            ConcatSizedByteBuffer(&hmac_key, (TPM2B *)&entity->entityAuth);

        rval = TpmComputeSessionHmac(sysContext,
                    session,
                    &pSessionsDataIn->auths[i],
                    false,
                    handle1,
                    handle2,
                    handle3,
                    &hmac_key);

        if (rval != TPM2_RC_SUCCESS)
            return rval;

        rval = CompareSizedByteBuffer((TPM2B *)&pSessionsDataIn->auths[i].hmac,
                                      (TPM2B *)&pSessionsDataOut->auths[i].hmac);
        if (rval != TPM2_RC_SUCCESS)
            return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    return rval;
}

TSS2_RC StartAuthSessionWithParams(
    SESSION **psession,
    TPMI_DH_OBJECT tpmKey,
    TPM2B_MAX_BUFFER *salt,
    TPMI_DH_ENTITY bind,
    TPM2B_AUTH *bindAuth,
    TPM2B_NONCE *nonceCaller,
    TPM2B_ENCRYPTED_SECRET *encryptedSalt,
    TPM2_SE sessionType,
    TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH algId,
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_RC rval;
    SESSION *session, *tmp;

    if (psession == NULL)
        return TSS2_SYS_RC_BAD_REFERENCE;

    session = calloc(1, sizeof(SESSION));

    if (!session)
        return TSS2_SYS_RC_GENERAL_FAILURE;

    session->bind = bind;
    session->tpmKey = tpmKey;
    CopySizedByteBuffer((TPM2B *)&session->nonceOlder, (TPM2B *)nonceCaller);
    CopySizedByteBuffer((TPM2B *)&session->encryptedSalt, (TPM2B *)encryptedSalt);
    session->sessionType = sessionType;
    session->symmetric.algorithm = symmetric->algorithm;
    session->symmetric.keyBits.sym = symmetric->keyBits.sym;
    session->symmetric.mode.sym = symmetric->mode.sym;
    session->authHash = algId;
    if (bindAuth != NULL)
        CopySizedByteBuffer((TPM2B *)&session->authValueBind, (TPM2B *)bindAuth);

    if (session->tpmKey != TPM2_RH_NULL)
        CopySizedByteBuffer((TPM2B *)&session->salt, (TPM2B *)salt);

    rval = StartAuthSession(session, tctiContext);
    if (rval != TSS2_RC_SUCCESS) {
        free(session);
        return rval;
    }
    /* Make sure this session handle is not already in the table */
    HASH_FIND_INT(sessions, &session->sessionHandle, tmp);
    if (tmp)
        HASH_DEL(sessions, tmp);

    HASH_ADD_INT(sessions, sessionHandle, session);
    *psession = session;
    return TSS2_RC_SUCCESS;
}

void EndAuthSession(SESSION *session)
{
    HASH_DEL(sessions, session);
    free(session);
}

void RollNonces(SESSION *session, TPM2B_NONCE *new_nonce)
{
    session->nonceOlder = session->nonceNewer;
    session->nonceNewer = *new_nonce;
}

TSS2_RC
TpmCalcPHash(
    TSS2_SYS_CONTEXT *sysContext,
    TPM2_HANDLE handle1,
    TPM2_HANDLE handle2,
    TPM2_HANDLE handle3,
    TPMI_ALG_HASH authHash,
    bool command,
    TPM2B_DIGEST *pHash)
{
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *tcti_context;
    UINT32 i;
    TPM2B_NAME name1, name2, name3;
    TPM2B_MAX_BUFFER hashInput;
    UINT8 *hashInputPtr;
    size_t parametersSize;
    const uint8_t *startParams;
    TPM2_CC cmdCode;

    name1.size = 0;
    name2.size = 0;
    name3.size = 0;
    hashInput.size = 0;

    rval = Tss2_Sys_GetTctiContext(sysContext, &tcti_context);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    if (command) {
        rval = TpmHandleToName(tcti_context, handle1, &name1);
        if (rval != TPM2_RC_SUCCESS)
                return rval;

        rval = TpmHandleToName(tcti_context, handle2, &name2);
        if (rval != TPM2_RC_SUCCESS)
            return rval;

        rval = TpmHandleToName(tcti_context, handle3, &name3);
        if (rval != TPM2_RC_SUCCESS)
            return rval;

        rval = Tss2_Sys_GetCpBuffer(sysContext, &parametersSize, &startParams);
        if (rval != TPM2_RC_SUCCESS)
            return rval;
    } else {
        rval = Tss2_Sys_GetRpBuffer(sysContext, &parametersSize, &startParams);
        if (rval != TPM2_RC_SUCCESS)
            return rval;

        hashInputPtr = &(hashInput.buffer[hashInput.size]);
        /* This is response code. Assuming 0 (success) */
        *(UINT32 *)hashInputPtr = 0;
        hashInput.size += 4;
    }

    rval = Tss2_Sys_GetCommandCode(sysContext, (UINT8 *)&cmdCode);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    hashInputPtr = &(hashInput.buffer[hashInput.size]);
    *(UINT32 *)hashInputPtr = cmdCode;
    hashInput.size += 4;

    rval = ConcatSizedByteBuffer(&hashInput, (TPM2B *)&name1);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    rval = ConcatSizedByteBuffer(&hashInput, (TPM2B *)&name2);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    rval = ConcatSizedByteBuffer(&hashInput, (TPM2B *)&name3);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    if (hashInput.size + parametersSize > sizeof(hashInput.buffer))
        return TSS2_SYS_RC_INSUFFICIENT_BUFFER;

    for(i = 0; i < parametersSize; i++)
        hashInput.buffer[hashInput.size + i ] = startParams[i];

    hashInput.size += (UINT16)parametersSize;
    LOGBLOB_DEBUG(&hashInput.buffer[0], hashInput.size, "PHASH input bytes=");

    if (hashInput.size > sizeof(hashInput.buffer))
        return TSS2_SYS_RC_INSUFFICIENT_BUFFER;

    rval = hash(authHash, hashInput.buffer, hashInput.size, pHash);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    LOGBLOB_DEBUG(&pHash->buffer[0], pHash->size, "PHASH =");
    return rval;
}

UINT32 TpmHandleToName(
    TSS2_TCTI_CONTEXT *tcti_context,
    TPM2_HANDLE handle,
    TPM2B_NAME *name)
{
    TSS2_RC rval;
    TPM2B_NAME qualified_name = TPM2B_NAME_INIT;
    TPM2B_PUBLIC public;
    TPM2B_NV_PUBLIC nvPublic;
    TSS2_SYS_CONTEXT *sysContext;
    UINT8 *namePtr;

    if (!tcti_context || !name)
        return TSS2_SYS_RC_BAD_VALUE;

    namePtr = name->name;

    if (handle == TPM2_RH_NULL) {
        name->size = 0;
        return TSS2_RC_SUCCESS;
    }

    switch(handle >> TPM2_HR_SHIFT)
    {
        case TPM2_HT_NV_INDEX:
            sysContext = sapi_init_from_tcti_ctx(tcti_context);
            if (sysContext == NULL)
                return TSS2_SYS_RC_GENERAL_FAILURE;

            nvPublic.size = 0;
            rval = Tss2_Sys_NV_ReadPublic(sysContext, handle, 0,
                                          &nvPublic, name, 0);
            sapi_teardown(sysContext);
            break;

        case TPM2_HT_TRANSIENT:
        case TPM2_HT_PERSISTENT:
            sysContext = sapi_init_from_tcti_ctx(tcti_context);
            if (sysContext == NULL)
                return TSS2_SYS_RC_GENERAL_FAILURE;

            public.size = 0;
			rval = Tss2_Sys_ReadPublic(sysContext, handle, 0,
                                       &public, name, &qualified_name, 0);
            sapi_teardown(sysContext);
            break;

        default:
            rval = TPM2_RC_SUCCESS;
            name->size = sizeof(TPM2_HANDLE);
            *(TPM2_HANDLE *)namePtr = BE_TO_HOST_32(handle);
    }
    return rval;
}

TSS2_RC
KDFa(
    TPMI_ALG_HASH hashAlg,
    TPM2B *key,
    const char *label,
    TPM2B *contextU,
    TPM2B *contextV,
    UINT16 bits,
    TPM2B_MAX_BUFFER *resultKey)
{
    TPM2B_DIGEST digest;
    TPM2B_DIGEST tpm2bLabel, tpm2bBits, tpm2bi;
    TPM2B_DIGEST *bufferList[8];
    UINT32 val;
    TSS2_RC rval;
    int i, j;
    UINT16 bytes = bits / 8;

    resultKey->size = 0;
    tpm2bi.size = 4;
    tpm2bBits.size = 4;
    val = BE_TO_HOST_32(bits);
    memcpy(tpm2bBits.buffer, &val, 4);
    tpm2bLabel.size = strlen(label) + 1;
    memcpy(tpm2bLabel.buffer, label, tpm2bLabel.size);

    LOG_DEBUG("KDFA, hashAlg = %4.4x", hashAlg);
    LOGBLOB_DEBUG(&key->buffer[0], key->size, "KDFA, key =");
    LOGBLOB_DEBUG(&tpm2bLabel.buffer[0], tpm2bLabel.size, "KDFA, tpm2bLabel =");
    LOGBLOB_DEBUG(&contextU->buffer[0], contextU->size, "KDFA, contextU =");
    LOGBLOB_DEBUG(&contextV->buffer[0], contextV->size, "KDFA, contextV =");

    for (i = 1, j = 0; resultKey->size < bytes; j = 0) {
        val = BE_TO_HOST_32(i++);
        memcpy(tpm2bi.buffer, &val, 4);
        bufferList[j++] = (TPM2B_DIGEST *)&tpm2bi;
        bufferList[j++] = (TPM2B_DIGEST *)&tpm2bLabel;
        bufferList[j++] = (TPM2B_DIGEST *)contextU;
        bufferList[j++] = (TPM2B_DIGEST *)contextV;
        bufferList[j++] = (TPM2B_DIGEST *)&tpm2bBits;
        bufferList[j++] = NULL;

        for (j = 0; bufferList[j] != NULL; j++) {
            LOGBLOB_DEBUG(&bufferList[j]->buffer[0], bufferList[j]->size, "bufferlist[%d]:", j);
            ;
        }

        rval = hmac(hashAlg, key->buffer, key->size, bufferList, &digest);
        if (rval != TPM2_RC_SUCCESS) {
            LOGBLOB_ERROR(digest.buffer, digest.size, "HMAC Failed rval = %d", rval);
            return rval;
        }

        ConcatSizedByteBuffer(resultKey, (TPM2B *)&digest);
    }

    /* Truncate the result to the desired size. */
    resultKey->size = bytes;
    LOGBLOB_DEBUG(&resultKey->buffer[0], resultKey->size, "KDFA, resultKey = ");
    return TPM2_RC_SUCCESS;
}
