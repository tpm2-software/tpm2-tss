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

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//  Procedure:	CopyCommandHeader
// 
//  Input:
//          
//  Output:	None
// 
//  Description:	
// 
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

void InitSysContextFields(
    TSS2_SYS_CONTEXT *sysContext
    )
{
    SYS_CONTEXT->tpmVersionInfoValid = 0;
    SYS_CONTEXT->decryptAllowed = 0;
    SYS_CONTEXT->encryptAllowed = 0;
    SYS_CONTEXT->decryptNull = 0;
    SYS_CONTEXT->authAllowed = 0;
    SYS_CONTEXT->decryptSession = 0;
    SYS_CONTEXT->encryptSession = 0;
    SYS_CONTEXT->prepareCalledFromOneCall = 0;
    SYS_CONTEXT->completeCalledFromOneCall = 0;

    SYS_CONTEXT->rval = TSS2_RC_SUCCESS;
    SYS_CONTEXT->nextData = SYS_CONTEXT->tpmInBuffPtr;
}

void CopyCommandHeader( _TSS2_SYS_CONTEXT_BLOB *sysContext, TPM_CC commandCode )
{
   SYS_CONTEXT->rval = TSS2_RC_SUCCESS;
  
  ((TPM20_Header_In *) sysContext->tpmInBuffPtr)->tag = CHANGE_ENDIAN_WORD( TPM_ST_NO_SESSIONS );

  ((TPM20_Header_In *) sysContext->tpmInBuffPtr)->commandCode = CHANGE_ENDIAN_DWORD( commandCode );

  SYS_CONTEXT->rval = TSS2_RC_SUCCESS;

  SYS_CONTEXT->nextData = SYS_CONTEXT->tpmInBuffPtr + sizeof( TPM20_Header_In );
}

TPM_RC FinishCommand( _TSS2_SYS_CONTEXT_BLOB *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray, 
    UINT32 *responseSize )
{  
    if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
        return SYS_CONTEXT->rval;

    // Now set the command size field, now that we know the size of the whole command.
    // WILL NEED TO TO THIS DIFFERENTLY.  OR MAYBE NOT AT ALL HERE.
//    ((TPM20_Header_In *) sysContext->tpmInBuffPtr)->commandSize = CHANGE_ENDIAN_DWORD( ( (UINT8 *)otherData ) -
//            (UINT8 *)&( ( TPM20_Header_In *) sysContext->tpmInBuffPtr )->tag );

    SYS_CONTEXT->rval = Tss2_Sys_Execute( (TSS2_SYS_CONTEXT *)sysContext );

    return( SYS_CONTEXT->rval );
}


// Common to all _Prepare
TSS2_RC CommonPreparePrologue(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_CC commandCode 
)
{
	int numCommandHandles;

    InitSysContextFields( sysContext );

    // Need to check stage here.
    if( SYS_CONTEXT->previousStage != CMD_STAGE_INITIALIZE &&
            SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE &&
            SYS_CONTEXT->previousStage != CMD_STAGE_PREPARE  )
    {
        SYS_CONTEXT->rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else
    {
        CopyCommandHeader( SYS_CONTEXT, commandCode );

        SYS_CONTEXT->numResponseHandles = GetNumResponseHandles( commandCode );

        SYS_CONTEXT->commandCodeSwapped = CHANGE_ENDIAN_DWORD( commandCode );

        SYS_CONTEXT->paramsSize = (UINT32 *)&(((TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr ) )->otherData ) +
                GetNumResponseHandles( commandCode );

        numCommandHandles = GetNumCommandHandles( commandCode );
        SYS_CONTEXT->cpBuffer = SYS_CONTEXT->nextData + numCommandHandles * sizeof(UINT32);
    }

    return SYS_CONTEXT->rval;
}

// Common to all _Prepare
TSS2_RC CommonPrepareEpilogue(
    TSS2_SYS_CONTEXT *sysContext
)
{
   if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
        return SYS_CONTEXT->rval;
    
    SYS_CONTEXT->cpBufferUsedSize = SYS_CONTEXT->nextData - SYS_CONTEXT->cpBuffer;

    // Set current command size.
    ((TPM20_Header_In *) SYS_CONTEXT->tpmInBuffPtr)->commandSize =
            CHANGE_ENDIAN_DWORD( SYS_CONTEXT->nextData - SYS_CONTEXT->tpmInBuffPtr );

    SYS_CONTEXT->previousStage = CMD_STAGE_PREPARE;

    return SYS_CONTEXT->rval;
}

// Common to all _Complete
TSS2_RC CommonComplete( TSS2_SYS_CONTEXT *sysContext )
{
    if( sysContext == NULL )
    {
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    else if( SYS_CONTEXT->previousStage != CMD_STAGE_RECEIVE_RESPONSE )
    {
        SYS_CONTEXT->rval = TSS2_SYS_RC_BAD_SEQUENCE;
    }
    else if( SYS_CONTEXT->rval == TSS2_RC_SUCCESS )
    {
        SYS_CONTEXT->nextData = (UINT8 *)( SYS_CONTEXT->paramsSize );

        if( CHANGE_ENDIAN_WORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr )  )->tag ) == TPM_ST_SESSIONS )
        {
            // Save params size.
            Unmarshal_UINT32( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &( SYS_CONTEXT->nextData ),
                    &( SYS_CONTEXT->rpBufferUsedSize ), &(SYS_CONTEXT->rval ) );
        }

        SYS_CONTEXT->rpBuffer = SYS_CONTEXT->nextData;
    }

    return SYS_CONTEXT->rval;
}

TSS2_RC CommonOneCall(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    )
{
    TSS2_RC     rval = TSS2_RC_SUCCESS;
    UINT32      responseSize;

    if( SYS_CONTEXT->rval != TSS2_RC_SUCCESS )
        return SYS_CONTEXT->rval;

    if( cmdAuthsArray != 0 )
    {
        SYS_CONTEXT->rval = Tss2_Sys_SetCmdAuths( sysContext, cmdAuthsArray );
    }

    if( rval == TSS2_RC_SUCCESS )
    {
        SYS_CONTEXT->rval = FinishCommand( SYS_CONTEXT, cmdAuthsArray, &responseSize );

        if ( SYS_CONTEXT->rval == TSS2_RC_SUCCESS ) 
        {
            if( SYS_CONTEXT->responseCode == TPM_RC_SUCCESS )
            {
                if( CHANGE_ENDIAN_WORD( ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr )  )->tag ) == TPM_ST_SESSIONS &&
                        rspAuthsArray != 0 )
                {
                    SYS_CONTEXT->rval = Tss2_Sys_GetRspAuths( sysContext, rspAuthsArray );
                }
            }
        }
    }
    return SYS_CONTEXT->rval;
}


TSS2_RC  CommonOneCallForNoResponseCmds(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    
    rval = CommonOneCall( sysContext, cmdAuthsArray, rspAuthsArray );

    if( rval == TSS2_RC_SUCCESS )
    {
        // command-specific

        rval = CommonComplete( sysContext );
    }

    return rval;
}

