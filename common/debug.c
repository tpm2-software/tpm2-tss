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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include <tss2/tpm20.h>
#include "debug.h"

int DebugPrintf( printf_type type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    if( type == RM_PREFIX )
        printf( "||  " );

    va_start( args, format );
    rval = vprintf( format, args );
    va_end (args);

    return rval;
}

void DebugPrintBuffer( printf_type type, UINT8 *buffer, UINT32 length )
{
    UINT32  i;
    
    for( i = 0; i < length; i++ )
    {
        if( ( i % 16 ) == 0 )
        {
            DebugPrintf(NO_PREFIX, "\n");
            if( type == RM_PREFIX )
                DebugPrintf(NO_PREFIX,  "||  " );
        }
        
        DebugPrintf(NO_PREFIX,  "%2.2x ", buffer[i] );
    }
    DebugPrintf(NO_PREFIX,  "\n\n" );
    fflush( stdout );
}

