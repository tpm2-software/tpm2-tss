//**********************************************************************;
// Copyright (c) 2015, 2017 Intel Corporation
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

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include "sapi/tpm20.h"
#include "tcti/tcti_socket.h"
#include "sysapi_util.h"
#include <sapi/tss2_tcti.h>
#include "sockets.h"
#include "tcti.h"
#define LOGMODULE tcti
#include "log/log.h"

TSS2_RC PlatformCommand(
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    char cmd )
{
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (tctiContext);
    int iResult = 0;            // used to return function results
    char sendbuf[] = { 0x0,0x0,0x0,0x0 };
    char recvbuf[] = { 0x0, 0x0, 0x0, 0x0 };
    TSS2_RC rval = TSS2_RC_SUCCESS;

    sendbuf[3] = cmd;

    // Send the command
    iResult = send (tcti_intel->otherSock, sendbuf, 4, MSG_NOSIGNAL);
    if (iResult == SOCKET_ERROR) {
        LOG_ERROR("send failed with error: %d", WSAGetLastError() );
        rval = TSS2_TCTI_RC_IO_ERROR;
    }
    else
    {
        LOGBLOB_DEBUG((uint8_t *)sendbuf, 4, "Send Bytes to socket #0x%x:", tcti_intel->otherSock);
        // Read result
        iResult = recv( tcti_intel->otherSock, recvbuf, 4, 0);
        if (iResult == SOCKET_ERROR) {
            LOG_ERROR("In PlatformCommand, recv failed (socket: 0x%x) with error: %d",
                    tcti_intel->otherSock, WSAGetLastError() );
            rval = TSS2_TCTI_RC_IO_ERROR;
        }
        else if( recvbuf[0] != 0 || recvbuf[1] != 0 || recvbuf[2] != 0 || recvbuf[3] != 0 )
        {
            LOG_ERROR( "PlatformCommand failed with error: %d", recvbuf[3] );
            rval = TSS2_TCTI_RC_IO_ERROR;
        }
        else
        {
            LOGBLOB_DEBUG((uint8_t *)recvbuf, 4, "Receive bytes from socket #0x%x:", tcti_intel->otherSock );
        }
    }
    return rval;
}
