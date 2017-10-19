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
#include "tss2_endian.h"

//
// This function is a helper function used to calculate cpHash and rpHash.
//
// NOTE:  for calculating cpHash, set responseCode to TPM_RC_NO_RESPONSE; this
// tells the function to leave it out of the calculation.
//
TPM_RC TpmCalcPHash( TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE handle1, TPM_HANDLE handle2,
    TPMI_ALG_HASH authHash, TPM_RC responseCode, TPM2B_DIGEST *pHash )
{
    TPM_RC rval = TPM_RC_SUCCESS;
    UINT32 i;
    TPM2B_NAME name1;
    TPM2B_NAME name2;
    TPM2B_MAX_BUFFER hashInput; // Byte stream to be hashed to create pHash
    UINT8 *hashInputPtr;
    size_t parametersSize;
    const uint8_t *startParams;
    TPM_CC cmdCode;

    name1.b.size = name2.b.size = 0;

    // Calculate pHash
    //

    // Only get names for commands
    if( responseCode == TPM_RC_NO_RESPONSE )
    {
        if( handle1 == TPM_HT_NO_HANDLE )
        {
            name1.t.size = 0;
        }
        else
        {
            // Get names for the handles
            rval = TpmHandleToName( handle1, &name1 );
            if( rval != TPM_RC_SUCCESS )
                return rval;
        }
    }

#ifdef DEBUG
    DebugPrintf( 0, "\n\nNAME1 = \n" );
    PrintSizedBuffer( &(name1.b) );
#endif

    // Only get names for commands
    if( responseCode == TPM_RC_NO_RESPONSE )
    {
        rval = Tss2_Sys_GetCpBuffer( sysContext, &parametersSize, &startParams);
        if( rval != TPM_RC_SUCCESS )
            return rval;

        if( handle2 == TPM_HT_NO_HANDLE )
        {
            name2.t.size = 0;
        }
        else
        {
            rval = TpmHandleToName( handle2, &name2 );
            if( rval != TPM_RC_SUCCESS )
                return rval;
        }
    }
    else
    {
        rval = Tss2_Sys_GetRpBuffer( sysContext, &parametersSize, &startParams);
        if( rval != TPM_RC_SUCCESS )
            return rval;
    }

#ifdef DEBUG
    DebugPrintf( 0, "\n\nNAME2 = \n" );
    PrintSizedBuffer( &(name2.b) );
#endif

    // Create pHash input byte stream:  first add response code, if any.
    hashInput.b.size = 0;
    if( responseCode != TPM_RC_NO_RESPONSE )
    {
        hashInputPtr = &( hashInput.t.buffer[hashInput.b.size] );
        *(UINT32 *)hashInputPtr = BE_TO_HOST_32(responseCode);
        hashInput.b.size += 4;
        hashInputPtr += 4;
    }

    // Create pHash input byte stream:  now add command code.
    rval = Tss2_Sys_GetCommandCode( sysContext, (UINT8 (*)[4])&cmdCode );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    hashInputPtr = &( hashInput.t.buffer[hashInput.b.size] );
    *(UINT32 *)hashInputPtr = cmdCode;
    hashInput.t.size += 4;

    // Create pHash input byte stream:  now add in names for the handles.
    rval = ConcatSizedByteBuffer( &hashInput, &( name1.b ) );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    rval = ConcatSizedByteBuffer( &hashInput, &( name2.b ) );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    if( ( hashInput.t.size + parametersSize ) <= sizeof( hashInput.t.buffer ) )
    {
        // Create pHash input byte stream:  now add in parameters byte stream
        for( i = 0; i < parametersSize; i++ )
            hashInput.t.buffer[hashInput.t.size + i ] = startParams[i];
        hashInput.t.size += (UINT16)parametersSize;
    }
    else
    {
        return( APPLICATION_ERROR( TSS2_BASE_RC_INSUFFICIENT_BUFFER ) );

    }
#ifdef DEBUG
    DebugPrintf( 0, "\n\nPHASH input bytes= \n" );
    PrintSizedBuffer( &(hashInput.b) );
#endif

    // Now hash the whole mess.
    if( hashInput.t.size > sizeof( hashInput.t.buffer ) )
    {
        rval = APPLICATION_ERROR( TSS2_BASE_RC_INSUFFICIENT_BUFFER );
    }
    else
    {
        rval = TpmHash( authHash, hashInput.t.size, &( hashInput.t.buffer[0] ), pHash );
        if( rval != TPM_RC_SUCCESS )
            return rval;
#ifdef DEBUG
        DebugPrintf( 0, "\n\nPHASH = " );
        PrintSizedBuffer( &(pHash->b) );
#endif
    }

    return rval;
}
