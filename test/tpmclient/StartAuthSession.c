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

#include <stdlib.h>

#include "tss2_sys.h"
#include "sysapi_util.h"

#include "tpmclient.int.h"
#include "../integration/context-util.h"
#include "../integration/sapi-util.h"
#define LOGMODULE testtpmclient
#include "util/log.h"

void RollNonces(SESSION *session, TPM2B_NONCE *newNonce)
{
    session->nonceOlder = session->nonceNewer;
    session->nonceNewer = *newNonce;
}

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
        return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;

    if (session->nonceOlder.size == 0)
        session->nonceOlder.size = GetDigestSize(session->authHash);

    memset(session->nonceOlder.buffer, '\0', session->nonceOlder.size);
    session->nonceNewer.size = session->nonceOlder.size;
    session->nonceTpmDecrypt.size = 0;
    session->nonceTpmEncrypt.size = 0;
    session->nvNameChanged = 0;

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
        return TSS2_APP_RC_BAD_REFERENCE;

    session = calloc(1, sizeof(SESSION));

    if (!session)
        return TSS2_APP_ERROR(TSS2_BASE_RC_MEMORY);

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
