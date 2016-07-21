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

#include <sapi/tpm20.h>
#include "sysapi_util.h"

#define SESSION_MARSHAL_UINT32( buffer, size, currentPtr, value, rval, exitLoc ) \
    Marshal_UINT32( buffer, size, currentPtr, value, rval ); \
    if( *rval != TSS2_RC_SUCCESS ) goto exitLoc;

#define SESSION_MARSHAL_UINT8( buffer, size, currentPtr, value, rval, exitLoc ) \
    Marshal_UINT8( buffer, size, currentPtr, value, rval ); \
    if( *rval != TSS2_RC_SUCCESS ) goto exitLoc;

#define SESSION_MARSHAL_SIMPLE_TPM2B( buffer, size, currentPtr, value, rval, exitLoc ) \
    Marshal_Simple_TPM2B( buffer, size, currentPtr, value, rval ); \
    if( *rval != TSS2_RC_SUCCESS ) goto exitLoc;

#define SESSION_UNMARSHAL_UINT32( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_UINT32( buffer, size, currentPtr, value, rval ); \
    if( *rval != TSS2_RC_SUCCESS ) goto exitLoc;

#define SESSION_UNMARSHAL_UINT8( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_UINT8( buffer, size, currentPtr, value, rval ); \
    if( *rval != TSS2_RC_SUCCESS ) goto exitLoc;

#define SESSION_UNMARSHAL_SIMPLE_TPM2B( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_Simple_TPM2B_NoSizeCheck( buffer, size, currentPtr, value, rval ); \
    if( *rval != TSS2_RC_SUCCESS ) goto exitLoc;


//static TPMI_SH_AUTH_SESSION authHandle1, authHandle2;

//
// Copy session data for commands that require it.
//
// Inputs:
//
//      pointer to pointer to sessionData area of command
//
//      pointer to session data to be copied into command buffer
//
// Outputs:
//
//      sessionDataPtr points to end byte past command buffer.  This allows
//          caller to set the commandSize field for the command.
//
TSS2_RC CopySessionDataIn( void **otherData, TPMS_AUTH_COMMAND const *sessionData, UINT32 *sessionSizePtr )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT8 *inBuffPtr = *otherData;
    TPMS_AUTH_COMMAND *sessionDataCopy = (TPMS_AUTH_COMMAND *)sessionData;

	if( sessionData == 0 )
	{
		rval = TSS2_SYS_RC_BAD_VALUE;
		goto exitCopySessionDataIn;
	}

    // Size of session data
    *sessionSizePtr += CHANGE_ENDIAN_DWORD(
            sizeof( TPMI_SH_AUTH_SESSION ) + sizeof( UINT16 ) +
            sessionData->nonce.t.size + sizeof( UINT8 ) +
            sizeof( UINT16 ) + sessionData->hmac.t.size );

    // copy session handle
    SESSION_MARSHAL_UINT32( inBuffPtr, *sessionSizePtr, (UINT8 **)otherData, sessionDataCopy->sessionHandle, &rval, exitCopySessionDataIn );

    // Copy nonce
    SESSION_MARSHAL_SIMPLE_TPM2B( inBuffPtr, *sessionSizePtr, (UINT8 **)otherData, &( sessionDataCopy->nonce.b ), &rval, exitCopySessionDataIn );

    // Copy attributes
    SESSION_MARSHAL_UINT8( inBuffPtr, *sessionSizePtr, (UINT8 **)otherData, (UINT8)( sessionDataCopy->sessionAttributes.val ), &rval, exitCopySessionDataIn );

    // Copy hmac data.
    SESSION_MARSHAL_SIMPLE_TPM2B( inBuffPtr, *sessionSizePtr, (UINT8 **)otherData, &( sessionDataCopy->hmac.b ), &rval, exitCopySessionDataIn );

exitCopySessionDataIn:
    return rval;
}

//
// Copy session data response from commands that return it.
//
// Inputs:
//
//      otherData:  pointer to pointer to start of sessions data in TPM output data stream
//
//      sessionData:  pointer to session data structure to be filled in with return data
//
// Outputs:
//
//      sessionData points to returned session data.
//
//      otherData points to next byte after the sessions data in the output data stream.
//          This allows subsequent calls to this function to get the next session data.		*nextData	CXX0017: Error: symbol "nextData" not found

//
TSS2_RC CopySessionDataOut( TPMS_AUTH_RESPONSE *sessionData, void **otherData, UINT8* outBuffPtr, UINT32 outBuffSize )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPMS_AUTH_RESPONSE *sessionDataCopy = (TPMS_AUTH_RESPONSE *)sessionData;

    if( sessionData == 0 )
        return rval;

    outBuffSize -= ((UINT8 *)*otherData - outBuffPtr + 1 );
    outBuffPtr = *otherData;

    // Copy nonceTpm
    SESSION_UNMARSHAL_SIMPLE_TPM2B( outBuffPtr, outBuffSize, (UINT8 **)otherData, &(sessionDataCopy->nonce.b), &rval, exitCopySessionDataOut );

    // Copy sessionAttributes
    SESSION_UNMARSHAL_UINT8( outBuffPtr, outBuffSize, (UINT8 **)otherData, (UINT8 *)&( sessionDataCopy->sessionAttributes ), &rval, exitCopySessionDataOut );

    // Copy hmac
    SESSION_UNMARSHAL_SIMPLE_TPM2B( outBuffPtr, outBuffSize, (UINT8 **)otherData, &(sessionDataCopy->hmac.b), &rval, exitCopySessionDataOut );

exitCopySessionDataOut:
    return rval;
}

//
// Copy all sessions data from sessions structure into command input byte stream.
//
TSS2_RC CopySessionsDataIn( void **otherData, TSS2_SYS_CMD_AUTHS const *sessionsDataIn )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT8    i = 0;
    UINT32   *sessionSizePtr = (UINT32 *)(*otherData);

    if( sessionsDataIn != 0 )
    {
        *sessionSizePtr = 0;

        if( sessionsDataIn->cmdAuthsCount != 0 )
        {
            // Skip over session size field
            *otherData = ( ( UINT32 *)*otherData ) + 1;

            for( i = 0; i < sessionsDataIn->cmdAuthsCount; i++ )
            {
                rval = CopySessionDataIn( otherData, sessionsDataIn->cmdAuths[i], sessionSizePtr );
                if( rval != TSS2_RC_SUCCESS )
                    break;
            }
        }
    }
    return rval;
}

TSS2_RC CopySessionsDataOut(
    TSS2_SYS_RSP_AUTHS *rspAuthsArray,
    void *otherData,
    TPM_ST tag,
    UINT8* outBuffPtr,
    UINT32 outBuffSize
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT8    i;

    if( rspAuthsArray != 0 )
    {
        if( tag == TPM_ST_SESSIONS )
        {
            if( rspAuthsArray != 0 )
            {
                for( i = 0; i < rspAuthsArray->rspAuthsCount; i++ )
                {
                    rval = CopySessionDataOut( rspAuthsArray->rspAuths[i], &otherData, outBuffPtr, outBuffSize );
                    if( rval != TSS2_RC_SUCCESS )
                        break;
                }
            }
        }
    }
    return rval;
}



