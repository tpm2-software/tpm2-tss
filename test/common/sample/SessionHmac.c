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
#include <stdio.h>
#include <stdlib.h>
#include "sysapi_util.h"

//
// This function calculates the session HMAC and updates session state.
//
UINT32 TpmComputeSessionHmac(
    TSS2_SYS_CONTEXT *sysContext,
    TPMS_AUTH_COMMAND *pSessionDataIn, // Pointer to session input struct
    TPM_HANDLE entityHandle,             // Used to determine if we're accessing a different
                                         // resource than the bound resoure.
    TPM_RC responseCode,                 // Response code for the command, 0xffff for "none" is
                                         // used to indicate that no response code is present
                                         // (used for calculating command HMACs vs response HMACs).
    TPM_HANDLE handle1,                  // First handle == 0xff000000 indicates no handle
    TPM_HANDLE handle2,                  // Second handle == 0xff000000 indicates no handle
    TPMA_SESSION sessionAttributes,      // Current session attributes
    TPM2B_DIGEST *result,                // Where the result hash is saved.
    TPM_RC sessionCmdRval
    )
{
    TPM2B_MAX_BUFFER hmacKey;
    TPM2B *bufferList[7];
    TPM2B_DIGEST pHash;
    SESSION *pSession = 0;
    TPM2B_AUTH authValue;
    TPM2B sessionAttributesByteBuffer;
    UINT16 i;
    TPM_RC rval;
    UINT8 nvNameChanged = 0;
    ENTITY *nvEntity;
    UINT8 commandCode[4] = { 0, 0, 0, 0 };
    UINT32 *cmdCodePtr;
    UINT32 cmdCode;

    hmacKey.b.size = 0;

    rval = GetSessionStruct( pSessionDataIn->sessionHandle, &pSession );
    if( rval != TPM_RC_SUCCESS )
    {
        return rval;
    }

    INIT_SIMPLE_TPM2B_SIZE( pHash );
    rval = ( *CalcPHash )( sysContext, handle1, handle2, pSession->authHash,
            responseCode, &pHash );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    // Use entityHandle to get authValue, if any.
    if( ( pSession->bind == TPM_RH_NULL ) ||
        ( ( pSession->bind != TPM_RH_NULL ) && ( pSession->bind == entityHandle ) ) )
    {
        rval = GetEntityAuth( entityHandle, &authValue );
        if( rval != TPM_RC_SUCCESS )
            authValue.t.size = 0;
    }
    else
    {
        authValue.t.size = 0;
    }

    rval = Tss2_Sys_GetCommandCode( sysContext, &commandCode );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    if( ( entityHandle >> HR_SHIFT ) == TPM_HT_NV_INDEX )
    {
        // If NV index, get status wrt to name change.  If name has changed,
        // we have to treat it as if its not the bound entity, even if it was
        // the bound entity.
        nvNameChanged = pSession->nvNameChanged;
    }

    rval = ConcatSizedByteBuffer( (TPM2B_MAX_BUFFER *)&hmacKey, &( pSession->sessionKey.b ) );

    if( ( pSession->bind == TPM_RH_NULL ) || ( pSession->bind != entityHandle )
            || nvNameChanged )
    {
        rval = ConcatSizedByteBuffer( (TPM2B_MAX_BUFFER *)&hmacKey, &( authValue.b ) );
    }

#ifdef  DEBUG
    DebugPrintf( 0, "\n\nhmacKey = " );
    PrintSizedBuffer( &(hmacKey.b) );
#endif

    // Create buffer list
    i = 0;
    bufferList[i++] = &pHash.b;
    bufferList[i++] = &( pSession->nonceNewer.b );
    bufferList[i++] = &( pSession->nonceOlder.b );
    bufferList[i++] = &( pSession->nonceTpmDecrypt.b );
    bufferList[i++] = &( pSession->nonceTpmEncrypt.b );
    sessionAttributesByteBuffer.size = 1;
    sessionAttributesByteBuffer.buffer[0] = *(UINT8 *)&sessionAttributes;
    bufferList[i++] = &( sessionAttributesByteBuffer );
    bufferList[i++] = 0;
    cmdCodePtr = (UINT32 *)&commandCode[0];
    cmdCode = *cmdCodePtr;

#ifdef  DEBUG
    for( i = 0; bufferList[i] != 0; i++ )
    {
        DebugPrintf( 0, "\n\nbufferlist[%d]:\n", i );
        PrintSizedBuffer( bufferList[i] );
    }
#endif

    rval = (*HmacFunctionPtr)( pSession->authHash, &hmacKey.b, &( bufferList[0] ), result );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    if( ( responseCode != TPM_RC_NO_RESPONSE ) &&
            ( cmdCode == TPM_CC_NV_Write ||
            cmdCode == TPM_CC_NV_Increment ||
            cmdCode == TPM_CC_NV_SetBits )
            )
    {
        rval = GetEntity( entityHandle, &nvEntity );
        if( rval != TPM_RC_SUCCESS )
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


TPM_RC ComputeCommandHmacs( TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE handle1,
    TPM_HANDLE handle2, TSS2_SYS_CMD_AUTHS *pSessionsDataIn,
    TPM_RC sessionCmdRval )
{
    uint8_t i;
    TPM_RC rval = TPM_RC_SUCCESS;
    TPM2B_AUTH *authPtr = 0;
    TPM_HANDLE entityHandle = TPM_HT_NO_HANDLE;

    // Note:  from Part 1, table 6, Use of Authorization/Session Blocks, we
    // can have at most two HMAC sessions per command.
    for( i = 0; ( i < 2 ) && ( i < pSessionsDataIn->cmdAuthsCount ); i++ )
    {
        authPtr = &( pSessionsDataIn->cmdAuths[i]->hmac );

        if( i == 0 || i == 1  )
        {
            entityHandle = handle1;
        }
        else
        {
            entityHandle = TPM_HT_NO_HANDLE;
        }

        if( authPtr != 0 )
        {
            rval = ( *ComputeSessionHmacPtr )( sysContext,  pSessionsDataIn->cmdAuths[i],
                    entityHandle, TPM_RC_NO_RESPONSE, handle1, handle2,
                    pSessionsDataIn->cmdAuths[i]->sessionAttributes,
                    authPtr, sessionCmdRval );
            if( rval != TPM_RC_SUCCESS )
                break;
        }
    }

    return rval;
}


TPM_RC CheckResponseHMACs( TSS2_SYS_CONTEXT *sysContext, TPM_RC responseCode,
    TSS2_SYS_CMD_AUTHS *pSessionsDataIn, TPM_HANDLE handle1, TPM_HANDLE handle2,
    TSS2_SYS_RSP_AUTHS *pSessionsDataOut )
{
    TPM_HANDLE entityHandle = TPM_HT_NO_HANDLE;
    TPM2B_DIGEST auth;
    TPM_RC rval = TPM_RC_SUCCESS;
    uint8_t i;

    // Check response HMACs, if any.
    if( responseCode == TPM_RC_SUCCESS )
    {
        for( i = 0; ( i < 2 ) && ( i < pSessionsDataIn->cmdAuthsCount ); i++ )
        {
            if( i == 0 || i == 1  )
            {
                entityHandle = handle1;
            }
            else
            {
                entityHandle = TPM_HT_NO_HANDLE;
            }

            if( ( pSessionsDataIn->cmdAuths[i]->sessionHandle >> HR_SHIFT ) == TPM_HT_HMAC_SESSION )
            {
                rval = ( *ComputeSessionHmacPtr )( sysContext,
                        pSessionsDataIn->cmdAuths[i], entityHandle,
                        responseCode, handle1, handle2,
                        pSessionsDataOut->rspAuths[i]->sessionAttributes,
                        &auth, TPM_RC_SUCCESS );
                if( rval != TPM_RC_SUCCESS )
                    return rval;

                rval = CompareSizedByteBuffer( &( auth.b ), &( pSessionsDataOut->rspAuths[i]->hmac.b ) );
                if( rval != TPM_RC_SUCCESS )
                    return APPLICATION_HMAC_ERROR(i+1);
            }
        }
    }
    return rval;
}


