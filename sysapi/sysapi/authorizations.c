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

#include <tpm20.h>   
#include <tss2_sysapi_util.h>   

TSS2_RC Tss2_Sys_SetCmdAuths(
    TSS2_SYS_CONTEXT            *sysContext,
    const TSS2_SYS_CMD_AUTHS 	*cmdAuthsArray
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    
    if( sysContext == NULL || cmdAuthsArray == 0 )
    {
        rval = TSS2_SYS_RC_BAD_REFERENCE;
    }
    else
    {
        SYS_CONTEXT->rval = TSS2_RC_SUCCESS;

        SYS_CONTEXT->authsCount = 0;

        if( cmdAuthsArray->cmdAuthsCount > MAX_SESSION_NUM )
        {
            rval = TSS2_SYS_RC_BAD_VALUE;
        }
        else if( SYS_CONTEXT->previousStage != CMD_STAGE_PREPARE )
        {
            rval = TSS2_SYS_RC_BAD_SEQUENCE;
        }
        else if( SYS_CONTEXT->authAllowed != 1 )
        {
            // Don't do anything.  Let the TPM return an error code.
        }
        else
        {
            uint8_t i;
            UINT32 authSize = 0;
            UINT64 newCmdSize = 0;

            if( cmdAuthsArray->cmdAuthsCount > 0 )
            {
                // Change command tag.
                ( (TPM20_Header_In *)( SYS_CONTEXT->tpmInBuffPtr ) )->tag = CHANGE_ENDIAN_WORD( TPM_ST_SESSIONS );

                // Calculate size needed for authorization area
                // and check for any null pointers.
                // Also check for decrypt/encrypt sessions.
                for( i = 0; i < cmdAuthsArray->cmdAuthsCount; i++ )
                {
                    // Check for null pointer.
                    if( cmdAuthsArray->cmdAuths[i] == 0 )
                    {
                        rval = TSS2_SYS_RC_BAD_VALUE;
                        break;
                    }
                    authSize += sizeof( TPMI_SH_AUTH_SESSION ); // Handle
                    authSize += sizeof( UINT16 ) + cmdAuthsArray->cmdAuths[i]->nonce.t.size; // nonce
                    authSize += sizeof( UINT8 ); // sessionAttribues
                    authSize += sizeof( UINT16 ) + cmdAuthsArray->cmdAuths[i]->hmac.t.size; // hmac

                    // Check for decrypt/encrypt sessions and set flags.   This is
                    // done to support the one-call function.
                    if( cmdAuthsArray->cmdAuths[i]->sessionAttributes.decrypt )
                        SYS_CONTEXT->decryptSession = 1;

                    if( cmdAuthsArray->cmdAuths[i]->sessionAttributes.encrypt )
                        SYS_CONTEXT->encryptSession = 1;
                }

                if( rval == TSS2_RC_SUCCESS )
                {
                    authSize += sizeof( UINT32 ); // authorization size field
                    newCmdSize = (UINT64)authSize + (UINT64)CHANGE_ENDIAN_DWORD( ( (TPM20_Header_In *)( SYS_CONTEXT->tpmInBuffPtr ) )->commandSize );

                    if( newCmdSize > (UINT64)( SYS_CONTEXT->maxCommandSize ) )
                    {
                        rval = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
                    }
                    else
                    {
                        void *otherData;

                        // We're going to have to move stuff around.
                        // First move current cpBuffer down.
                        rval = CopyMemReverse( SYS_CONTEXT->cpBuffer + authSize, SYS_CONTEXT->cpBuffer, SYS_CONTEXT->cpBufferUsedSize, SYS_CONTEXT->tpmInBuffPtr + SYS_CONTEXT->maxCommandSize );

                        if( rval == TSS2_RC_SUCCESS )
                        {
                            // Now copy in the authorization area.
                            otherData = SYS_CONTEXT->cpBuffer;
                            rval = CopySessionsDataIn( &otherData, cmdAuthsArray );

                            // Update cpBuffer        
                            SYS_CONTEXT->cpBuffer += authSize;

                            // Now update the command size.
                            ( (TPM20_Header_In *)( SYS_CONTEXT->tpmInBuffPtr ) )->commandSize = CHANGE_ENDIAN_DWORD( (UINT32)newCmdSize );

                            SYS_CONTEXT->authsCount = cmdAuthsArray->cmdAuthsCount;
                        }
                    }
                }
            }
        }
    }
    return rval;
}

TSS2_RC Tss2_Sys_GetRspAuths(
    TSS2_SYS_CONTEXT 		*sysContext,
    TSS2_SYS_RSP_AUTHS 		*rspAuthsArray
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    void *otherData, *otherDataSaved;

    if( sysContext == NULL || rspAuthsArray == NULL )
    {
        rval = TSS2_SYS_RC_BAD_REFERENCE;
    }
    else if( SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE ||
            CHANGE_ENDIAN_DWORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr ) )->responseCode ) != TPM_RC_SUCCESS ||
            SYS_CONTEXT->authAllowed == 0 )
    {
        rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else
    {
        int i = 0;
    
        SYS_CONTEXT->rval = TSS2_RC_SUCCESS;

        if( rspAuthsArray->rspAuthsCount == 0 )
        {
            rval = TSS2_SYS_RC_BAD_VALUE;
        }
        else
        {
            if( rspAuthsArray->rspAuthsCount != SYS_CONTEXT->authsCount )
            {
                rval = TSS2_SYS_RC_INVALID_SESSIONS;
            }
            else
            {
                // Get start of authorization area.
                otherData = SYS_CONTEXT->tpmOutBuffPtr;
                otherData = (UINT8 *)otherData + sizeof( TPM20_Header_Out ) - 1;
                otherData = (UINT8 *)otherData + SYS_CONTEXT->numResponseHandles * sizeof( TPM_HANDLE );
                otherData = (UINT8 *)otherData + CHANGE_ENDIAN_DWORD( *( SYS_CONTEXT->paramsSize ) ); 
                otherData = (UINT8 *)otherData + sizeof( UINT32 );

                otherDataSaved = otherData;

                if( TPM_ST_SESSIONS == CHANGE_ENDIAN_WORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr ) )->tag ) )
                {
                    for( i = 0; i < rspAuthsArray->rspAuthsCount; i++ )
                    {
                        // Before copying, make sure that we aren't going to go past the output buffer + the response size.
                        if( (UINT8 *)otherData > ( SYS_CONTEXT->tpmOutBuffPtr + CHANGE_ENDIAN_DWORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr ) )->responseSize ) ) )
                        {
                            rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
                            break;
                        }

                        otherData = (UINT8 *)otherData + sizeof( UINT16 ) + CHANGE_ENDIAN_WORD( *(UINT16 *)otherData ); // Nonce
                        if( (UINT8 *)otherData > ( SYS_CONTEXT->tpmOutBuffPtr + CHANGE_ENDIAN_DWORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr ) )->responseSize ) ) )
                        {
                            rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
                            break;
                        }

                        otherData = (UINT8 *)otherData + 1;  // session attributes.
                        if( (UINT8 *)otherData > ( SYS_CONTEXT->tpmOutBuffPtr + CHANGE_ENDIAN_DWORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr ) )->responseSize ) ) )
                        {
                            rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
                            break;
                        }

                        otherData = (UINT8 *)otherData + sizeof( UINT16 ) + CHANGE_ENDIAN_WORD( *(UINT16 *)otherData ); // hmac
                        if( (UINT8 *)otherData > ( SYS_CONTEXT->tpmOutBuffPtr + CHANGE_ENDIAN_DWORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr ) )->responseSize ) ) )
                        {
                            rval = TSS2_SYS_RC_MALFORMED_RESPONSE;
                            break;
                        }

                        // Make sure that we don't run past the valid authorizations.
                        if( ( i + 1 ) > rspAuthsArray->rspAuthsCount )
                        {
                            rval = TSS2_SYS_RC_INVALID_SESSIONS;
                            break;
                        }
                    }
                    if( rval == TSS2_RC_SUCCESS )
                    {
                        // Check that number of auths is equal to the number asked for.
                        // Can't see how this would actually happen, but left it in as a failsafe against
                        // future code modifications.
                        if( i != rspAuthsArray->rspAuthsCount )
                        {
                            rval = TSS2_SYS_RC_INVALID_SESSIONS;
                        }
                        else
                        {
                            // Get start of authorization area.
                            otherData = otherDataSaved;
                            rval = CopySessionsDataOut( rspAuthsArray, otherData,
                                    CHANGE_ENDIAN_WORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr ) )->tag ),
                                    SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize );
                        }
                    }
                }
            }
        }
    }
    return rval;
}
