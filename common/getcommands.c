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
#include <stdio.h>
#include <stdlib.h>
#include <tss2_sysapi_util.h>

#ifdef SAPI_CLIENT
void *(*gcMalloc)(size_t size) = malloc;
TSS2_RC level = TSS2_ERROR_LEVEL( TSS2_APP_ERROR_LEVEL );
#else
extern void *(*rmMalloc)(size_t size);
TSS2_RC level = TSS2_ERROR_LEVEL( TSS2_RESMGR_ERROR_LEVEL );
#endif    

// Get the TPM 2.0 commands supported by the TPM.
TSS2_RC GetCommands( TSS2_SYS_CONTEXT *resMgrSysContext, TPML_CCA **supportedCommands )
{
    UINT32      numCommands;
    TPMI_YES_NO	moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    TPMA_CC *commandPtr;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT32 i;
    
#ifdef SAPI_CLIENT
    void *(*gcMalloc)(size_t size) = malloc;
#else    
    void *(*gcMalloc)(size_t size) = rmMalloc;
#endif
    
    // First get the number of commands
    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_TOTAL_COMMANDS,
            1, 0, &capabilityData, 0 );
    if( rval == TPM_RC_SUCCESS &&
            capabilityData.capability == TPM_CAP_TPM_PROPERTIES &&
            capabilityData.data.tpmProperties.count == 1 &&
            capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_TOTAL_COMMANDS )
    {
        numCommands = capabilityData.data.tpmProperties.tpmProperty[0].value;
    }
    else
    {
        goto returnFromGetCommands;
    }

    // Allocate memory for them
    *supportedCommands = malloc( numCommands * sizeof( TPMA_CC ) + sizeof( UINT32 ) );
    if( !*supportedCommands )
    {
        rval = TSS2_BASE_RC_INSUFFICIENT_BUFFER + level;
        goto returnFromGetCommands;
    }

    for( commandPtr = &( ( *supportedCommands )->commandAttributes[0] ), ( *supportedCommands )->count = 0;
            ( *supportedCommands )->count < numCommands;
            ( *supportedCommands )->count += capabilityData.data.command.count,
                    commandPtr += capabilityData.data.command.count )
    {
        // Now get the command structures for all of them.
        rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
                TPM_CAP_COMMANDS, TPM_CC_FIRST,
                numCommands, &moreData, &capabilityData, 0 );

        if( rval == TPM_RC_SUCCESS &&
                capabilityData.capability == TPM_CAP_COMMANDS  &&
                capabilityData.data.command.count >= 1 )
        {
            for( i = 0; i < capabilityData.data.command.count; i ++ )
            {
                commandPtr[ ( *supportedCommands )->count + i ].val =
                        capabilityData.data.command.commandAttributes[i].val;
            }
        }
        else
        {
            break;
        }
    }
    
returnFromGetCommands:
    return rval;
}

//
// Searches in a list for command attributes bit field for a command code.
// Assumes that the supportedCommands structure has been populated by
// calling GetCommands beforehand.
//
// Returns:
//  1, if found.  In this case, cmdAttributes points to the attributes bit field.
//  0, if not found.  This means that the TPM doesn't support this command.
//  
UINT8 GetCommandAttributes( TPM_CC commandCode, TPML_CCA *supportedCommands, TPMA_CC *cmdAttributes )
{
    UINT32 i;
    UINT8 rval = 0;
    
    for( i = 0; i < supportedCommands->count; i++ )
    {
        if( (TPM_CC)( supportedCommands->commandAttributes[i].commandIndex ) == commandCode )
        {
            rval = 1;
            *cmdAttributes = supportedCommands->commandAttributes[i];
			break;
        }
    }

    return rval;
}