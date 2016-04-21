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

#include <tss2/tpm20.h>
#include "utils.h"
#include "sysapi_util.h"
#include "debug.h"
//#include "commonchecks.h"

//
// Used by some high level sample routines to copy the results.
//
void copyData( UINT8 *to, UINT8 *from, UINT32 length )
{
    if( to != 0 && from != 0 )
        memcpy( to, from, length );
}

TPM_RC CompareTPM2B( TPM2B *buffer1, TPM2B *buffer2 )
{
    if( buffer1->size != buffer2->size )
        return TPM_RC_FAILURE;
    for( int i = 0; i < buffer1->size; i++ )
    {
        if( buffer1->buffer[0] != buffer2->buffer[0] )
            return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

void PrintSizedBuffer( TPM2B *sizedBuffer )
{
    int i;

    for( i = 0; i < sizedBuffer->size; i++ )
    {
        DebugPrintf( NO_PREFIX, "%2.2x ", sizedBuffer->buffer[i] );

        if( ( (i+1) % 16 ) == 0 )
        {
            DebugPrintf( NO_PREFIX, "\n" );
        }
    }
    DebugPrintf( NO_PREFIX, "\n" );
}
