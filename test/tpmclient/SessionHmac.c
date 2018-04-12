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

static UINT32
TpmComputeSessionHmac(
    TSS2_SYS_CONTEXT *sysContext,
    SESSION *session,
    TPMS_AUTH_COMMAND *pSessionDataIn,
    TPM2_HANDLE entityHandle,
    bool command,
    TPM2_HANDLE handle1,
    TPM2_HANDLE handle2,
    TPMA_SESSION sessionAttributes,
    TPM2B_DIGEST *result)
{
    TPM2B_MAX_BUFFER hmacKey;
    TPM2B_DIGEST *bufferList[7];
    TPM2B_DIGEST pHash;
    TPM2B_AUTH authValue;
    TPM2B sessionAttributesByteBuffer;
    UINT16 i;
    TSS2_RC rval;
    UINT8 nvNameChanged = 0;
    ENTITY *nvEntity;
    TPM2_CC cmdCode;

    hmacKey.size = 0;

    INIT_SIMPLE_TPM2B_SIZE(pHash);
    rval = TpmCalcPHash(sysContext, handle1, handle2,
                        session->authHash, command, &pHash);
    if (rval != TPM2_RC_SUCCESS)
        return rval;

    // Use entityHandle to get authValue, if any.
    if (session->bind == TPM2_RH_NULL ||
        (session->bind != TPM2_RH_NULL && session->bind == entityHandle))
    {
        rval = GetEntityAuth(entityHandle, &authValue);
        if(rval != TPM2_RC_SUCCESS)
            authValue.size = 0;
    }
    else
    {
        authValue.size = 0;
    }

    rval = Tss2_Sys_GetCommandCode(sysContext, (UINT8 *)&cmdCode);
    if(rval != TPM2_RC_SUCCESS)
        return rval;

    // cmdCode comes back as BigEndian; not suited for comparisons below.
    cmdCode = BE_TO_HOST_32(cmdCode);

    if((entityHandle >> TPM2_HR_SHIFT) == TPM2_HT_NV_INDEX)
    {
        // If NV index, get status wrt to name change.  If name has changed,
        // we have to treat it as if it's not the bound entity, even if it was
        // the bound entity.
        nvNameChanged = session->nvNameChanged;
    }

    rval = ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&hmacKey, (TPM2B *)&session->sessionKey);
    if(rval != TPM2_RC_SUCCESS)
        return rval;

    if((session->bind == TPM2_RH_NULL) || (session->bind != entityHandle)
            || nvNameChanged)
    {
        rval = ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&hmacKey, (TPM2B *)&authValue);
        if(rval != TPM2_RC_SUCCESS)
            return rval;
    }
    LOGBLOB_DEBUG(&hmacKey.buffer[0], hmacKey.size, "hmacKey=");

    // Create buffer list
    i = 0;
    bufferList[i++] = (TPM2B_DIGEST *)&pHash;
    bufferList[i++] = (TPM2B_DIGEST *)&session->nonceNewer;
    bufferList[i++] = (TPM2B_DIGEST *)&session->nonceOlder;
    bufferList[i++] = (TPM2B_DIGEST *)&session->nonceTpmDecrypt;
    bufferList[i++] = (TPM2B_DIGEST *)&session->nonceTpmEncrypt;
    sessionAttributesByteBuffer.size = 1;
    sessionAttributesByteBuffer.buffer[0] = *(UINT8 *)&sessionAttributes;
    bufferList[i++] = (TPM2B_DIGEST *)&sessionAttributesByteBuffer;
    bufferList[i++] = 0;

#if LOGLEVEL == LOGLEVEL_DEBUG || \
    LOGLEVEL == LOGLEVEL_TRACE
        for (int j = 0; bufferList[j] != 0; j++)
            LOGBLOB_DEBUG(&bufferList[j]->buffer[0], bufferList[j]->size, "bufferlist[%d]:", j);
#endif

    rval = hmac(session->authHash, hmacKey.buffer, hmacKey.size, bufferList, result);
    if (rval != TPM2_RC_SUCCESS) {
        LOGBLOB_ERROR(result->buffer, result->size, "HMAC Failed rval = %d !!!", rval);
        return rval;
    }



    if (command && (cmdCode == TPM2_CC_NV_Write ||
                    cmdCode == TPM2_CC_NV_Increment ||
                    cmdCode == TPM2_CC_NV_SetBits)) {
        rval = GetEntity(entityHandle, &nvEntity);

        if (rval != TPM2_RC_SUCCESS)
            return rval;
        // Only change session's nvNameChanged parameter when
        // the NV index's name changes due to a write.
        if (nvEntity->nvNameChanged == 0) {
            session->nvNameChanged = 1;
            nvEntity->nvNameChanged = 1;
        }
    }

    return rval;
}


TSS2_RC ComputeCommandHmacs(
        TSS2_SYS_CONTEXT *sysContext,
        SESSION *session,
        TPM2_HANDLE handle1,
        TPM2_HANDLE handle2,
        TSS2L_SYS_AUTH_COMMAND *pSessionsDataIn)
{
    uint8_t i;
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_AUTH *authPtr = 0;
    TPM2_HANDLE entityHandle = TPM2_HT_NO_HANDLE;

    // Note:  from Part 1, table 6, Use of Authorization/Session Blocks, we
    // can have at most two HMAC sessions per command.
    for (i = 0; i < 2 && i < pSessionsDataIn->count; i++) {
        authPtr = &(pSessionsDataIn->auths[i].hmac);
        entityHandle = handle1;

        if (!authPtr)
            break;

        rval = TpmComputeSessionHmac(sysContext,
                session,
                &pSessionsDataIn->auths[i],
                entityHandle,
                true,
                handle1,
                handle2,
                pSessionsDataIn->auths[i].sessionAttributes,
                authPtr);
        if (rval != TPM2_RC_SUCCESS)
            break;
    }
    return rval;
}

TSS2_RC CheckResponseHMACs(
        TSS2_SYS_CONTEXT *sysContext,
        SESSION *session,
        TSS2L_SYS_AUTH_COMMAND *pSessionsDataIn,
        TPM2_HANDLE handle1,
        TPM2_HANDLE handle2,
        TSS2L_SYS_AUTH_RESPONSE *pSessionsDataOut)
{
    TPM2_HANDLE entityHandle = TPM2_HT_NO_HANDLE;
    TPM2B_DIGEST auth;
    TSS2_RC rval = TPM2_RC_SUCCESS;
    uint8_t i;

    for (i = 0; i < 2 && i < pSessionsDataIn->count; i++) {
        entityHandle = handle1;

        if ((pSessionsDataIn->auths[i].sessionHandle >> TPM2_HR_SHIFT) == TPM2_HT_HMAC_SESSION)
        {
            rval = TpmComputeSessionHmac(sysContext,
                        session,
                        &pSessionsDataIn->auths[i],
                        entityHandle,
                        false,
                        handle1,
                        handle2,
                        pSessionsDataOut->auths[i].sessionAttributes,
                        &auth);
            if (rval != TPM2_RC_SUCCESS)
                return rval;

            rval = CompareSizedByteBuffer((TPM2B *)&auth, (TPM2B *)&pSessionsDataOut->auths[i].hmac);
            if (rval != TPM2_RC_SUCCESS)
                return APPLICATION_HMAC_ERROR(i+1);
        }
    }

    return rval;
}
