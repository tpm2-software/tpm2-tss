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

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include "tpm20.h"
#include "debug.h"

UINT8 rmDebugPrefix = 0;

void DebugPrintBuffer( UINT8 *buffer, UINT32 length )
{
    UINT32  i;
    
    for( i = 0; i < length; i++ )
    {
        if( ( i % 16 ) == 0 )
        {
            (*printfFunction)(NO_PREFIX, "\n");
            PrintRMDebugPrefix();
        }
        
        (*printfFunction)(NO_PREFIX,  "%2.2x ", buffer[i] );
    }
    (*printfFunction)(NO_PREFIX,  "\n\n" );
    fflush( stdout );
}

void DebugPrintBufferOpen( UINT8 *buffer, UINT32 length )
{
    UINT32  i;

    OpenOutFile( &outFp );

    if( outFp != 0 )
    {
        for( i = 0; i < length; i++ )
        {
            if( ( i % 16 ) == 0 )
            {
                (*printfFunction)(NO_PREFIX, "\n");
                PrintRMDebugPrefix();
            }

            (*printfFunction)(NO_PREFIX,  "%2.2x ", buffer[i] );
        }
        (*printfFunction)(NO_PREFIX,  "\n\n" );
        fflush( stdout );
    }

    CloseOutFile( &outFp );
}

#ifdef SHARED_OUT_FILE
static int openCnt = 0;

void OpenOutFile( FILE **outFp )
{
    if( *outFp == 0 )
    {
        if( 0 == strcmp( outFileName, "" ) )
        {
            *outFp = stdout;
        }
        else
        {
            if( openCnt == 0 )
            {
                do
                {
                    *outFp = fopen( &outFileName[0], "a+" );
                }
                while( *outFp == 0 );
            }
            openCnt++;
        }
    }
    else
    {
        if( ( *outFp != stdout ) && ( openCnt < 0xff ) )
            openCnt++;
    }
}

void CloseOutFile( FILE **outFp )
{
    if( 0 != strcmp( outFileName, "" ) )
    {
        if( *outFp != 0 )
        {
            if( openCnt == 1 && *outFp != stdout )
            {
                fclose( *outFp );
                *outFp = 0;
            }
            if( openCnt > 0 )
                openCnt--;
        }
    }
}
#else
void OpenOutFile( FILE **outFilePtr )
{
    *outFilePtr = stdout;
}    

void CloseOutFile( FILE **outFilePtr )
{
}
#endif

void PrintRMDebugPrefix()
{
    if( rmDebugPrefix )
        (*printfFunction)(NO_PREFIX,  "||  " );
}

