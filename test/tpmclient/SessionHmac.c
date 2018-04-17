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

#include <stdio.h>
#include <stdlib.h>

#include "tss2_sys.h"

#include "../integration/sapi-util.h"
#include "../integration/session-util.h"
#include "tpmclient.int.h"
#include "sysapi_util.h"
#include "util/tss2_endian.h"
#define LOGMODULE test
#include "util/log.h"

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
    TPM2B_DIGEST pHash;
    TPM2B sessionAttributesByteBuffer = {
        .size = 1,
        .buffer = pSessionDataIn->sessionAttributes
    };
    UINT16 i;
    TSS2_RC rval;
    TPM2_CC cmdCode;

    INIT_SIMPLE_TPM2B_SIZE(pHash);
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

    for (i = 0; i < pSessionsDataIn->count; i++) {
        if (handles[i] == TPM2_RH_NULL)
            break;

        rval = GetEntity(handles[i], &entity);
        if (rval)
            return rval;

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

    for (i = 0; i < pSessionsDataIn->count; i++) {
        if (handles[i] == TPM2_RH_NULL)
            break;

        rval = GetEntity(handles[i], &entity);
        if (rval)
            return rval;

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
            return APPLICATION_HMAC_ERROR(i+1);
    }
    return rval;
}
