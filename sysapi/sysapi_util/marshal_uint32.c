//**********************************************************************;
// Copyright (c) 2015, 2016 Intel Corporation
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

void Marshal_UINT32( UINT8 *inBuffPtr, UINT32 maxCommandSize, UINT8 **nextData, UINT32 value, TSS2_RC *rval )
{
    if( *rval != TSS2_RC_SUCCESS )
        return;

    *rval = CheckDataPointers( inBuffPtr, nextData );
    if( *rval != TSS2_RC_SUCCESS )
        return;

    *rval = CheckOverflow( inBuffPtr, maxCommandSize, *nextData, sizeof(UINT32) );
    if( *rval != TSS2_RC_SUCCESS )
        return;

    *( (UINT32 *)*nextData ) = CHANGE_ENDIAN_DWORD( value );
    *nextData = *nextData + sizeof( UINT32 );
}
