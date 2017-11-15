//**********************************************************************;
// Copyright (c) 2015, Intel Corporation All rights reserved.
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
#include "sysapi_util.h"

void Unmarshal_Simple_TPM2B_NoSizeCheck( UINT8 *outBuffPtr, UINT32 maxResponseSize, UINT8 **nextData, TPM2B *outTPM2B, TSS2_RC *rval )
{
//deleted for now--spec issues with nested TPM2B's
#if 0
    INT64 callerAllocatedSize;
#endif
    int i;
    UINT16 length;

    if( *rval == TSS2_RC_SUCCESS )
    {
        if( outBuffPtr == 0 || nextData == 0 || *nextData == 0 )
        {
            *rval = TSS2_SYS_RC_BAD_REFERENCE;
        }
        else
        {
            if( *rval == TSS2_RC_SUCCESS )
            {
                length = CHANGE_ENDIAN_WORD( *(UINT16 *)*nextData );

                if( outTPM2B != 0 )
                {
                    Unmarshal_UINT16( outBuffPtr, maxResponseSize, nextData, &( outTPM2B->size ), rval );
                }
                else
                {
                    // Let low level function deal with NULL output pointer.
                    Unmarshal_UINT16( outBuffPtr, maxResponseSize, nextData, 0, rval );
                }

                if( *rval == TSS2_RC_SUCCESS )
                {
                    // Copy to output TPM2B.
                    for( i = 0; i < length && *rval == TSS2_RC_SUCCESS; i++ )
                    {
                        if( outTPM2B != 0 )
                        {
                            Unmarshal_UINT8( outBuffPtr, maxResponseSize, nextData,  &( outTPM2B->buffer[i] ), rval );
                        }
                        else
                        {
                            // Let low level function deal with NULL output pointer.
                            Unmarshal_UINT8( outBuffPtr, maxResponseSize, nextData, 0, rval );
                        }

                        if( *rval != TSS2_RC_SUCCESS )
                        {
                            break;
                        }
                    }
                }
            }
        }
    }
}

