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


//
// Concatenate two sized byte buffers from left to right.
//
// Inputs:
//
//      result -- pointer to TPM2B_MAX_BUFFER to hold result
//      addBuffer -- pointer to TPM2B buffer to be concatenated with result
//
// Outputs:
//
//      result contains the concatenation, if size permits
//      and it's size is updated accordingly.
//
//      If result isn't large enough, result doesn't change.
//
//      returned value is 0 for success, 1 for failure
//
TPM_RC ConcatSizedByteBuffer( TPM2B_MAX_BUFFER *result, TPM2B *addBuffer )
{
    int i;

    if( ( result->t.size + addBuffer->size ) > MAX_DIGEST_BUFFER )
        return TSS2_SYS_RC_BAD_VALUE;
    else
    {
        for( i = 0; i < addBuffer->size; i++ )
            result->t.buffer[i + result->t.size] = addBuffer->buffer[i];

        result->t.size += addBuffer->size;
        
        return TPM_RC_SUCCESS;
    }
}
