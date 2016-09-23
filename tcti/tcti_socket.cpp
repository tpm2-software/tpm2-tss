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
// NOTE:  this file is used in two places:  application SAPI (to
// communicate with RM) and RM calls to SAPI (to communicate with
// TPM simulator.
//
// There will be a few small differences between the two uses and
// these will be handled via #ifdef's and different header files.
//

//
// NOTE:  uncomment following if you think you need to see all
// socket communications.
//
//#define DEBUG_SOCKETS

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "sysapi_util.h"
#include "debug.h"
#include "commonchecks.h"
#include "logging.h"

#ifdef __cplusplus
extern "C" {
#endif

static TSS2_RC tctiRecvBytes( TSS2_TCTI_CONTEXT *tctiContext, SOCKET sock, unsigned char *data, int len )
{
    TSS2_RC result = 0;
    result = recvBytes( sock, data, len);
    if ( (INT32)result == SOCKET_ERROR) {
        TCTI_LOG( tctiContext, NO_PREFIX, "In recvBytes, recv failed (socket: 0x%x) with error: %d\n", sock, WSAGetLastError() );
        return TSS2_TCTI_RC_IO_ERROR;
    }
#ifdef DEBUG_SOCKETS
    TCTI_LOG( tctiContext, NO_PREFIX, "Receive Bytes from socket #0x%x: \n", sock );
    TCTI_LOG_BUFFER( tctiContext, NO_PREFIX, data, len );
#endif

    return TSS2_RC_SUCCESS;
}

static TSS2_RC tctiSendBytes( TSS2_TCTI_CONTEXT *tctiContext, SOCKET sock, const unsigned char *data, int len )
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

#ifdef DEBUG_SOCKETS
    TCTI_LOG( tctiContext, NO_PREFIX, "Send Bytes to socket #0x%x: \n", sock );
    TCTI_LOG_BUFFER( tctiContext, NO_PREFIX, (UINT8 *)data, len );
#endif

    ret = sendBytes( sock, data, len);
    if (ret != TSS2_RC_SUCCESS)
        TCTI_LOG( tctiContext, NO_PREFIX, "In recvBytes, recv failed (socket: 0x%x) with error: %d\n", sock, WSAGetLastError() );
    return ret;
}

TSS2_RC SendSessionEndSocketTcti(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    UINT8 tpmCmdServer )
{
    UINT32 tpmSendCommand = TPM_SESSION_END;  // Value for "send command" to MS simulator.
    SOCKET sock;
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( tpmCmdServer )
    {
        sock = TCTI_CONTEXT_INTEL->tpmSock;
    }
    else
    {
        sock = TCTI_CONTEXT_INTEL->otherSock;
    }

    tpmSendCommand = CHANGE_ENDIAN_DWORD(tpmSendCommand);
    rval = tctiSendBytes( tctiContext, sock, (char unsigned *)&tpmSendCommand, 4 );

    return( rval );
}

TSS2_RC SocketSendTpmCommand(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    size_t             command_size,      /* in */
    uint8_t           *command_buffer     /* in */
    )
{
    UINT32 tpmSendCommand = MS_SIM_TPM_SEND_COMMAND;  // Value for "send command" to MS simulator.
    UINT32 cnt, cnt1;
    UINT8 locality;
    TSS2_RC rval = TSS2_RC_SUCCESS;

#ifdef DEBUG
    UINT32 commandCode;
    printf_type rmPrefix;
#endif

    rval = CommonSendChecks( tctiContext, command_buffer );
    if( rval != TSS2_RC_SUCCESS )
    {
        goto returnFromSocketSendTpmCommand;
    }

#ifdef DEBUG
    if( ( ( TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.rmDebugPrefix == 1 )
        rmPrefix = RM_PREFIX;
    else
        rmPrefix = NO_PREFIX;

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgEnabled == 1 )
    {
        TCTI_LOG( tctiContext, rmPrefix, "" );
		commandCode = CHANGE_ENDIAN_DWORD( ( (TPM20_Header_In *)command_buffer )->commandCode );
#ifdef DEBUG_SOCKETS
        TCTI_LOG( tctiContext, NO_PREFIX, "Command sent on socket #0x%x: %s\n", TCTI_CONTEXT_INTEL->tpmSock, strTpmCommandCode( commandCode ) );
#else
        TCTI_LOG( tctiContext, NO_PREFIX, "Cmd sent: %s\n", strTpmCommandCode( commandCode ) );
#endif
    }
#endif
    // Size TPM 1.2 and TPM 2.0 headers overlap exactly, we can use
    // either 1.2 or 2.0 header to get the size.
    cnt = CHANGE_ENDIAN_DWORD(((TPM20_Header_In *) command_buffer)->commandSize);

    // Send TPM_SEND_COMMAND
    tpmSendCommand = CHANGE_ENDIAN_DWORD(tpmSendCommand);
    rval = tctiSendBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&tpmSendCommand, 4 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;

    // Send the locality
    locality = (UINT8)( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality;
    rval = tctiSendBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&locality, 1 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;

#ifdef DEBUG
    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgEnabled == 1 )
    {
        TCTI_LOG( tctiContext, rmPrefix, "Locality = %d", ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality );
    }
#endif

    // Send number of bytes.
    cnt1 = cnt;
    cnt = CHANGE_ENDIAN_DWORD(cnt);
    rval = tctiSendBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&cnt, 4 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;

    // Send the TPM command buffer
    rval = tctiSendBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)command_buffer, cnt1 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;

#ifdef DEBUG
    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgEnabled == 1 )
    {
        DEBUG_PRINT_BUFFER( rmPrefix, command_buffer, cnt1 );
    }
#endif
    ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 1;

returnFromSocketSendTpmCommand:

    if( rval == TSS2_RC_SUCCESS )
    {
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage = TCTI_STAGE_SEND_COMMAND;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.responseSizeReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.protocolResponseSizeReceived = 0;
    }

    return rval;
}

TSS2_RC SocketCancel(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( tctiContext == 0 )
    {
        rval = TSS2_TCTI_RC_BAD_REFERENCE;
    }
    else if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent != 1 )
    {
        rval = TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    else
    {
        rval = (TSS2_RC)PlatformCommand( tctiContext, MS_SIM_CANCEL_ON );
#if 0
        if( rval == TSS2_RC_SUCCESS )
        {
            rval = (TSS2_RC)PlatformCommand( tctiContext, MS_SIM_CANCEL_OFF );
            if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED )
            {
                TCTI_LOG( tctiContext, NO_PREFIX, "%s sent cancel ON command:\n", interfaceName );
            }
        }
#endif
    }

    return rval;
}

TSS2_RC SocketSetLocality(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    uint8_t           locality     /* in */
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( tctiContext == 0 )
    {
        rval = TSS2_TCTI_RC_BAD_REFERENCE;
    }
    else if( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality != locality )
    {
        if ( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent == 1 )
        {
            rval = TSS2_TCTI_RC_BAD_SEQUENCE;
        }
        else
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality = locality;
        }
    }

    return rval;
}

void SocketFinalize(
    TSS2_TCTI_CONTEXT *tctiContext       /* in */
    )
{
    if( tctiContext != NULL )
    {
        // Send session end messages to servers.
        SendSessionEndSocketTcti( tctiContext, 1 );
        SendSessionEndSocketTcti( tctiContext, 0 );

        CloseSockets( TCTI_CONTEXT_INTEL->otherSock, TCTI_CONTEXT_INTEL->tpmSock );
    }
}

TSS2_RC SocketReceiveTpmResponse(
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    size_t          *response_size,     /* out */
    unsigned char   *response_buffer,    /* in */
    int32_t         timeout
    )
{
    UINT32 trash;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    fd_set readFds;
    struct timeval tv, *tvPtr;
    int32_t timeoutMsecs = timeout % 1000;
    int iResult;
    unsigned char responseSizeDelta = 0;
    printf_type rmPrefix;

    rval = CommonReceiveChecks( tctiContext, response_size, response_buffer );
    if( rval != TSS2_RC_SUCCESS )
    {
        goto retSocketReceiveTpmResponse;
    }

    if( ( ( TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.rmDebugPrefix == 1 )
        rmPrefix = RM_PREFIX;
    else
        rmPrefix = NO_PREFIX;

    if( timeout == TSS2_TCTI_TIMEOUT_BLOCK )
    {
        tvPtr = 0;
    }
    else
    {
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = timeoutMsecs * 1000;
        tvPtr = &tv;
    }

    FD_ZERO( &readFds );
    FD_SET( TCTI_CONTEXT_INTEL->tpmSock, &readFds );

    iResult = select( TCTI_CONTEXT_INTEL->tpmSock+1, &readFds, 0, 0, tvPtr );
    if( iResult == 0 )
    {
        TCTI_LOG( tctiContext, rmPrefix, "select failed due to timeout, socket #: 0x%x\n", TCTI_CONTEXT_INTEL->tpmSock );
        rval = TSS2_TCTI_RC_TRY_AGAIN;
        goto retSocketReceiveTpmResponse;
    }
    else if( iResult == SOCKET_ERROR )
    {
        TCTI_LOG( tctiContext, rmPrefix, "select failed with socket error: %d\n", WSAGetLastError() );
        rval = TSS2_TCTI_RC_IO_ERROR;
        goto retSocketReceiveTpmResponse;
    }
    else if ( iResult != 1 )
    {
        TCTI_LOG( tctiContext, rmPrefix, "select failed, read the wrong # of bytes: %d\n", iResult );
        rval = TSS2_TCTI_RC_IO_ERROR;
        goto retSocketReceiveTpmResponse;
    }

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.protocolResponseSizeReceived != 1 )
    {
        // Receive the size of the response.
        rval = tctiRecvBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)& (((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize ), 4 );
        if( rval != TSS2_RC_SUCCESS )
            goto retSocketReceiveTpmResponse;

        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize = CHANGE_ENDIAN_DWORD( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize );
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.protocolResponseSizeReceived = 1;
    }

    if( response_buffer == NULL )
    {
        // In this case, just return the size
        *response_size = ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.protocolResponseSizeReceived = 1;
        goto retSocketReceiveTpmResponse;
    }

    if( *response_size < ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize )
    {
        *response_size = ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize;
        rval = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;


        // If possible, receive tag from TPM.
        if( *response_size >= sizeof( TPM_ST ) && ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived == 0 )
        {
            if( TSS2_RC_SUCCESS != tctiRecvBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->tag ), 2 ) )
            {
                goto retSocketReceiveTpmResponse;
            }
            else
            {
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived = 1;
            }
        }

        // If possible, receive response size from TPM
        if( *response_size >= ( sizeof( TPM_ST ) + sizeof( TPM_RC ) ) && ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.responseSizeReceived == 0 )
        {
            if( TSS2_RC_SUCCESS != tctiRecvBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->responseSize ), 4 ) )
            {
                goto retSocketReceiveTpmResponse;
            }
            else
            {
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize = CHANGE_ENDIAN_DWORD( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize );
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.responseSizeReceived = 1;
            }
        }
    }
    else
    {
        if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgEnabled == 1 &&
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize > 0 )
        {
#ifdef DEBUG
            TCTI_LOG( tctiContext, rmPrefix, "Response Received: " );
#endif
#ifdef DEBUG_SOCKETS
            TCTI_LOG( tctiContext, rmPrefix, "from socket #0x%x:\n", TCTI_CONTEXT_INTEL->tpmSock );
#endif
        }

        if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived == 1 )
        {
            *(TPM_ST *)response_buffer = ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->tag;
            responseSizeDelta += sizeof( TPM_ST );
            response_buffer += sizeof( TPM_ST );
        }

        if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.responseSizeReceived == 1 )
        {
            *(TPM_RC *)response_buffer = CHANGE_ENDIAN_DWORD( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->responseSize );
            responseSizeDelta += sizeof( TPM_RC );
            response_buffer += sizeof( TPM_RC );
        }

        // Receive the TPM response.
        rval = tctiRecvBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)response_buffer, ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize - responseSizeDelta );
        if( rval != TSS2_RC_SUCCESS )
            goto retSocketReceiveTpmResponse;

#ifdef DEBUG
        if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgEnabled == 1 )
        {
            DEBUG_PRINT_BUFFER( rmPrefix, response_buffer, ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize );
        }
#endif

        // Receive the appended four bytes of 0's
        rval = tctiRecvBytes( tctiContext, TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&trash, 4 );
        if( rval != TSS2_RC_SUCCESS )
            goto retSocketReceiveTpmResponse;
    }

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize < *response_size )
    {
        *response_size = ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize;
    }

    ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 0;

    // Turn cancel off.
    if( rval == TSS2_RC_SUCCESS )
    {
        rval = (TSS2_RC)PlatformCommand( tctiContext, MS_SIM_CANCEL_OFF );
    }
    else
    {
        // Ignore return value so earlier error code is preserved.
        PlatformCommand( tctiContext, MS_SIM_CANCEL_OFF );
    }

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgEnabled== 1 )
    {
//        TCTI_LOG( tctiContext, NO_PREFIX,  "%s sent cancel OFF command:\n", interfaceName );
    }

retSocketReceiveTpmResponse:
    if( rval == TSS2_RC_SUCCESS &&
		response_buffer != NULL )
    {
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage = TCTI_STAGE_RECEIVE_RESPONSE;
    }

    return rval;
}

#ifdef __cplusplus
}
#endif

#define HOSTNAME_LENGTH 200
#define PORT_LENGTH 4

/**
 * This function sends the Microsoft simulator the MS_SIM_POWER_ON and
 * MS_SIM_NV_ON commands using the PlatformCommand mechanism. Without
 * these the simulator will respond with zero sized buffer which causes
 * the TSS to freak out. Sending this command more than once is harmelss
 * so it's advisable to call this function as part of the TCTI context
 * initialization just to be sure.
 *
 * NOTE: The caller will still need to call Tss2_Sys_Startup. If they
 * don't, an error will be returned from each call till they do but
 * the error will at least be meaningful (TPM_RC_INITIALIZE).
 */
static TSS2_RC InitializeMsTpm2Simulator(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    TSS2_TCTI_CONTEXT_INTEL *intel_tctiCtx;
    TSS2_RC rval;

    intel_tctiCtx = (TSS2_TCTI_CONTEXT_INTEL*)tctiContext;
    rval = PlatformCommand( tctiContext ,MS_SIM_POWER_ON );
    if( rval != TSS2_RC_SUCCESS ) {
        CloseSockets( intel_tctiCtx->otherSock, intel_tctiCtx->tpmSock );
        return rval;
    }
    rval = PlatformCommand( tctiContext, MS_SIM_NV_ON );
    if( rval != TSS2_RC_SUCCESS )
        CloseSockets( intel_tctiCtx->otherSock, intel_tctiCtx->tpmSock );

    return rval;
}

TSS2_RC InitSocketTcti (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    size_t *contextSize,            // IN/OUT
    const TCTI_SOCKET_CONF *conf,              // IN
    const uint8_t serverSockets
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    SOCKET otherSock;
    SOCKET tpmSock;

    if( tctiContext == NULL )
    {
        *contextSize = sizeof( TSS2_TCTI_CONTEXT_INTEL );
        return TSS2_RC_SUCCESS;
    }
    else
    {
        // Init TCTI context.
        TSS2_TCTI_MAGIC( tctiContext ) = TCTI_MAGIC;
        TSS2_TCTI_VERSION( tctiContext ) = TCTI_VERSION;
        TSS2_TCTI_TRANSMIT( tctiContext ) = SocketSendTpmCommand;
        TSS2_TCTI_RECEIVE( tctiContext ) = SocketReceiveTpmResponse;
        TSS2_TCTI_FINALIZE( tctiContext ) = SocketFinalize;
        TSS2_TCTI_CANCEL( tctiContext ) = SocketCancel;
        TSS2_TCTI_GET_POLL_HANDLES( tctiContext ) = 0;
        TSS2_TCTI_SET_LOCALITY( tctiContext ) = SocketSetLocality;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.debugMsgEnabled = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality = 3;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.rmDebugPrefix = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.responseSizeReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.protocolResponseSizeReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->currentTctiContext = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage = TCTI_STAGE_INITIALIZE;
        TCTI_LOG_CALLBACK( tctiContext ) = conf->logCallback;
        TCTI_LOG_BUFFER_CALLBACK( tctiContext ) = conf->logBufferCallback;
        TCTI_LOG_DATA( tctiContext ) = conf->logData;

        rval = (TSS2_RC) InitSockets( conf->hostname, conf->port, serverSockets, &otherSock, &tpmSock, TCTI_LOG_CALLBACK( tctiContext ), TCTI_LOG_DATA( tctiContext) );
        if( rval == TSS2_RC_SUCCESS )
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->otherSock = otherSock;
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->tpmSock = tpmSock;
            rval = InitializeMsTpm2Simulator( tctiContext );
        }
        else
        {
            CloseSockets( otherSock, tpmSock);
        }
    }

    return rval;
}
