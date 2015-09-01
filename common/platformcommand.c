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

//
// NOTE:  this file is only used when the TPM simulator is being used
// as the TPM device.  It is used in two places:  application SAPI (to
// communicate platform commands to the RM) and when RM needs
// to send platform commands to the simulator.
//

//
// NOTE:  uncomment following if you think you need to see all
// socket communications.
//
//#define DEBUG_SOCKETS

#define DEBUG

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include "tpm20.h"
#include "tpmsockets.h"
#include "tss2_sysapi_util.h"
#include "debug.h"
#include "tss2_tcti.h"
#include "tss2_tcti_util.h"

TSS2_RC PlatformCommand(
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    char cmd )
{
    int iResult = 0;            // used to return function results
    char sendbuf[] = { 0x0,0x0,0x0,0x0 };
    char recvbuf[] = { 0x0, 0x0, 0x0, 0x0 };
	TSS2_RC rval = TSS2_RC_SUCCESS;

    if( simulator )
    {
        sendbuf[3] = cmd;

        OpenOutFile( &outFp );

        // Send the command
        iResult = send( TCTI_CONTEXT_INTEL->otherSock, sendbuf, 4, 0 );

        if (iResult == SOCKET_ERROR) {
            (*printfFunction)(NO_PREFIX, "send failed with error: %d\n", WSAGetLastError() );
            closesocket(TCTI_CONTEXT_INTEL->otherSock);
            WSACleanup();
            rval = TSS2_TCTI_RC_IO_ERROR;
        }
        else
        {
#ifdef DEBUG_SOCKETS
            (*printfFunction)( rmDebugPrefix, "Send Bytes to socket #0x%x: \n", TCTI_CONTEXT_INTEL->otherSock );
            DebugPrintBuffer( (UINT8 *)sendbuf, 4 );
#endif

            // Read result
            iResult = recv( TCTI_CONTEXT_INTEL->otherSock, recvbuf, 4, 0);
            if (iResult == SOCKET_ERROR) {
                (*printfFunction)(NO_PREFIX, "In PlatformCommand, recv failed (socket: 0x%x) with error: %d\n",
                        TCTI_CONTEXT_INTEL->otherSock, WSAGetLastError() );
                closesocket(TCTI_CONTEXT_INTEL->otherSock);
                WSACleanup();
                rval = TSS2_TCTI_RC_IO_ERROR;
            }
            else if( recvbuf[0] != 0 || recvbuf[1] != 0 || recvbuf[2] != 0 || recvbuf[3] != 0 )
            {
                (*printfFunction)(NO_PREFIX, "PlatformCommand failed with error: %d\n", recvbuf[3] );
                closesocket(TCTI_CONTEXT_INTEL->otherSock);
                WSACleanup();
                rval = TSS2_TCTI_RC_IO_ERROR;
            }
            else
            {
#ifdef DEBUG_SOCKETS
                (*printfFunction)(NO_PREFIX, "Receive bytes from socket #0x%x: \n", TCTI_CONTEXT_INTEL->otherSock );
                DebugPrintBuffer( (UINT8 *)recvbuf, 4 );
#endif
            }
        }

        CloseOutFile( &outFp );
    }
    return rval;
}
