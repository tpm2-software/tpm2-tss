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

#include "sample.h"
#include "sysapi_util.h"
#include "util/tss2_endian.h"
#define LOGMODULE test
#include "util/log.h"

//
// This function calculates the session HMAC and updates session state.
//
UINT32 TpmComputeSessionHmac(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_AUTH_COMMAND *pSessionDataIn, // Pointer to session input struct
    TPM2_HANDLE entityHandle,             // Used to determine if we're accessing a different
                                         // resource than the bound resource.
    TSS2_RC responseCode,                 // Response code for the command, 0xffff for "none" is
                                         // used to indicate that no response code is present
                                         // (used for calculating command HMACs vs response HMACs).
    TPM2_HANDLE handle1,                  // First handle == 0xff000000 indicates no handle
    TPM2_HANDLE handle2,                  // Second handle == 0xff000000 indicates no handle
    TPMA_SESSION sessionAttributes,      // Current session attributes
    TPM2B_DIGEST *result,                // Where the result hash is saved.
    TSS2_RC sessionCmdRval
    )
{
    TPM2B_MAX_BUFFER hmacKey;
    TPM2B *bufferList[7];
    TPM2B_DIGEST pHash;
    SESSION *pSession = 0;
    TPM2B_AUTH authValue;
    TPM2B sessionAttributesByteBuffer;
    UINT16 i;
    TSS2_RC rval;
    UINT8 nvNameChanged = 0;
    ENTITY *nvEntity;
    TPM2_CC cmdCode;

    hmacKey.size = 0;

    rval = GetSessionStruct( pSessionDataIn->sessionHandle, &pSession );
    if( rval != TPM2_RC_SUCCESS )
    {
        return rval;
    }

    INIT_SIMPLE_TPM2B_SIZE( pHash );
    rval = TpmCalcPHash(sysContext, handle1, handle2, pSession->authHash,
            responseCode, &pHash);
    if( rval != TPM2_RC_SUCCESS )
        return rval;

    // Use entityHandle to get authValue, if any.
    if( ( pSession->bind == TPM2_RH_NULL ) ||
        ( ( pSession->bind != TPM2_RH_NULL ) && ( pSession->bind == entityHandle ) ) )
    {
        rval = GetEntityAuth( entityHandle, &authValue );
        if( rval != TPM2_RC_SUCCESS )
            authValue.size = 0;
    }
    else
    {
        authValue.size = 0;
    }

    rval = Tss2_Sys_GetCommandCode( sysContext, (UINT8 *)&cmdCode );
    if( rval != TPM2_RC_SUCCESS )
        return rval;

    // cmdCode comes back as BigEndian; not suited for comparisons below.
    cmdCode = BE_TO_HOST_32(cmdCode);

    if( ( entityHandle >> TPM2_HR_SHIFT ) == TPM2_HT_NV_INDEX )
    {
        // If NV index, get status wrt to name change.  If name has changed,
        // we have to treat it as if it's not the bound entity, even if it was
        // the bound entity.
        nvNameChanged = pSession->nvNameChanged;
    }

    rval = ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&hmacKey, (TPM2B *)&pSession->sessionKey);
    if( rval != TPM2_RC_SUCCESS )
        return rval;

    if( ( pSession->bind == TPM2_RH_NULL ) || ( pSession->bind != entityHandle )
            || nvNameChanged )
    {
        rval = ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&hmacKey, (TPM2B *)&authValue);
        if( rval != TPM2_RC_SUCCESS )
            return rval;
    }
    LOGBLOB_DEBUG(&hmacKey.buffer[0], hmacKey.size, "hmacKey=");

    // Create buffer list
    i = 0;
    bufferList[i++] = (TPM2B *)&pHash;
    bufferList[i++] = (TPM2B *)&pSession->nonceNewer;
    bufferList[i++] = (TPM2B *)&pSession->nonceOlder;
    bufferList[i++] = (TPM2B *)&pSession->nonceTpmDecrypt;
    bufferList[i++] = (TPM2B *)&pSession->nonceTpmEncrypt;
    sessionAttributesByteBuffer.size = 1;
    sessionAttributesByteBuffer.buffer[0] = *(UINT8 *)&sessionAttributes;
    bufferList[i++] = &sessionAttributesByteBuffer;
    bufferList[i++] = 0;

#if LOGLEVEL == LOGLEVEL_DEBUG || \
    LOGLEVEL == LOGLEVEL_TRACE
        for(int j = 0; bufferList[j] != 0; j++ )
        {
            LOGBLOB_DEBUG(&bufferList[j]->buffer[0], bufferList[j]->size, 
                "bufferlist[%d]:", j);
        }
#endif

    rval = TpmHmac(pSession->authHash, (TPM2B *)&hmacKey, bufferList, result);
    if( rval != TPM2_RC_SUCCESS )
        return rval;

    if( ( responseCode != TPM2_RC_NO_RESPONSE ) &&
            ( cmdCode == TPM2_CC_NV_Write ||
            cmdCode == TPM2_CC_NV_Increment ||
            cmdCode == TPM2_CC_NV_SetBits )
            )
    {
        rval = GetEntity( entityHandle, &nvEntity );
        if( rval != TPM2_RC_SUCCESS )
        {
            return rval;
        }
        else
        {
            // Only change session's nvNameChanged parameter when
            // the NV index's name changes due to a write.
            if( nvEntity->nvNameChanged == 0 )
            {
                pSession->nvNameChanged = 1;
                nvEntity->nvNameChanged = 1;
            }
        }
    }

    return rval;
}


TSS2_RC ComputeCommandHmacs( TSS2_SYS_CONTEXT *sysContext, TPM2_HANDLE handle1,
    TPM2_HANDLE handle2, TSS2L_SYS_AUTH_COMMAND *pSessionsDataIn,
    TSS2_RC sessionCmdRval )
{
    uint8_t i;
    TSS2_RC rval = TPM2_RC_SUCCESS;
    TPM2B_AUTH *authPtr = 0;
    TPM2_HANDLE entityHandle = TPM2_HT_NO_HANDLE;

    // Note:  from Part 1, table 6, Use of Authorization/Session Blocks, we
    // can have at most two HMAC sessions per command.
    for( i = 0; ( i < 2 ) && ( i < pSessionsDataIn->count ); i++ )
    {
        authPtr = &( pSessionsDataIn->auths[i].hmac );
        entityHandle = handle1;

        if( authPtr != 0 )
        {
            rval = TpmComputeSessionHmac( sysContext,  &pSessionsDataIn->auths[i],
                    entityHandle, TPM2_RC_NO_RESPONSE, handle1, handle2,
                    pSessionsDataIn->auths[i].sessionAttributes,
                    authPtr, sessionCmdRval );
            if( rval != TPM2_RC_SUCCESS )
                break;
        }
    }

    return rval;
}


TSS2_RC CheckResponseHMACs( TSS2_SYS_CONTEXT *sysContext, TSS2_RC responseCode,
    TSS2L_SYS_AUTH_COMMAND *pSessionsDataIn, TPM2_HANDLE handle1, TPM2_HANDLE handle2,
    TSS2L_SYS_AUTH_RESPONSE *pSessionsDataOut )
{
    TPM2_HANDLE entityHandle = TPM2_HT_NO_HANDLE;
    TPM2B_DIGEST auth;
    TSS2_RC rval = TPM2_RC_SUCCESS;
    uint8_t i;

    // Check response HMACs, if any.
    if( responseCode == TPM2_RC_SUCCESS )
    {
        for( i = 0; ( i < 2 ) && ( i < pSessionsDataIn->count ); i++ )
        {
            entityHandle = handle1;

            if( ( pSessionsDataIn->auths[i].sessionHandle >> TPM2_HR_SHIFT ) == TPM2_HT_HMAC_SESSION )
            {
                rval = TpmComputeSessionHmac( sysContext,
                        &pSessionsDataIn->auths[i], entityHandle,
                        responseCode, handle1, handle2,
                        pSessionsDataOut->auths[i].sessionAttributes,
                        &auth, TPM2_RC_SUCCESS );
                if( rval != TPM2_RC_SUCCESS )
                    return rval;

                rval = CompareSizedByteBuffer((TPM2B *)&auth, (TPM2B *)&pSessionsDataOut->auths[i].hmac);
                if( rval != TPM2_RC_SUCCESS )
                    return APPLICATION_HMAC_ERROR(i+1);
            }
        }
    }
    return rval;
}
