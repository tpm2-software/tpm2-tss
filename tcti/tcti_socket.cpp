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

#include <tss2/tpm20.h>
#include <tcti/tcti_socket.h>
#include "sysapi_util.h"
#include "debug.h"
#include "commonchecks.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SAPI_CLIENT
extern int TpmClientPrintf( UINT8 type, const char *format, ... );
int (*printfFunction)( UINT8 type, const char *format, ...) = TpmClientPrintf;
#else
extern int ResMgrPrintf( UINT8 type, const char *format, ... );
int (*printfFunction)( UINT8 type, const char *format, ...) = ResMgrPrintf;
#endif

extern UINT8 simulator;

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
    rval = sendBytes( sock, (char *)&tpmSendCommand, 4 );

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
    UINT32 commandCode    ;
    
#ifdef SAPI_CLIENT    
    UINT8 debugMsgLevel, statusBits;
#endif

    rval = CommonSendChecks( tctiContext, command_buffer );
    if( rval != TSS2_RC_SUCCESS )
    {
        goto returnFromSocketSendTpmCommand;
    }
            
    commandCode = CHANGE_ENDIAN_DWORD( ( (TPM20_Header_In *)command_buffer )->commandCode );

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED )
    {
#ifdef DEBUG
        (*printfFunction)(NO_PREFIX, "\n" );
        if( commandCode >= TPM_CC_NV_UndefineSpaceSpecial && commandCode <= TPM_CC_PolicyNvWritten )     
            (*printfFunction)(rmDebugPrefix, "Cmd sent: %s\n", commandCodeStrings[ commandCode - TPM_CC_FIRST ] );            
        else
            (*printfFunction)(rmDebugPrefix, "Cmd sent: 0x%4.4x\n", CHANGE_ENDIAN_DWORD(commandCode ) );
#endif
#ifdef DEBUG_SOCKETS
        (*printfFunction)(rmDebugPrefix, "Command sent on socket #0x%x: %s\n", TCTI_CONTEXT_INTEL->tpmSock, commandCodeStrings[ commandCode - TPM_CC_FIRST ]  );
#endif        
    }
    // Size TPM 1.2 and TPM 2.0 headers overlap exactly, we can use
    // either 1.2 or 2.0 header to get the size.
    cnt = CHANGE_ENDIAN_DWORD(((TPM20_Header_In *) command_buffer)->commandSize);

    // Send TPM_SEND_COMMAND
    tpmSendCommand = CHANGE_ENDIAN_DWORD(tpmSendCommand);
    rval = sendBytes( TCTI_CONTEXT_INTEL->tpmSock, (char *)&tpmSendCommand, 4 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;
                
    // Send the locality
    locality = (UINT8)( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality;
    rval = sendBytes( TCTI_CONTEXT_INTEL->tpmSock, (char *)&locality, 1 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;

#ifdef SAPI_CLIENT    
    // Send the debug level
    debugMsgLevel = (UINT8)( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.debugMsgLevel;
    rval = sendBytes( TCTI_CONTEXT_INTEL->tpmSock, (char *)&debugMsgLevel, 1 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;

    // Send status bits
    statusBits = (UINT8)( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent;
    statusBits |= ( (UINT8)( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.rmDebugPrefix ) << 1;
    rval = sendBytes( TCTI_CONTEXT_INTEL->tpmSock, (char *)&statusBits, 1 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;
#endif
    
#ifdef DEBUG
    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED )
    {
        (*printfFunction)(rmDebugPrefix, "Locality = %d", ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality );
    }
#endif
    
    // Send number of bytes.
    cnt1 = cnt;
    cnt = CHANGE_ENDIAN_DWORD(cnt);
    rval = sendBytes( TCTI_CONTEXT_INTEL->tpmSock, (char *)&cnt, 4 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;
    
    // Send the TPM command buffer
    rval = sendBytes( TCTI_CONTEXT_INTEL->tpmSock, (char *)command_buffer, cnt1 );
    if( rval != TSS2_RC_SUCCESS )
        goto returnFromSocketSendTpmCommand;
    
#ifdef DEBUG
    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED )
    {
        DEBUG_PRINT_BUFFER( command_buffer, cnt1 );
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
                (*printfFunction)(NO_PREFIX, "%s sent cancel ON command:\n", interfaceName );
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

void CloseSockets( SOCKET otherSock, SOCKET tpmSock)
{
    closesocket(otherSock);
    closesocket(tpmSock);
}    

TSS2_RC SocketFinalize(
    TSS2_TCTI_CONTEXT *tctiContext       /* in */
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    
    if( tctiContext == NULL )
    {
        rval = TSS2_TCTI_RC_BAD_REFERENCE;
    }
    else
    {
        // Send session end messages to servers.
        SendSessionEndSocketTcti( tctiContext, 1 );
        SendSessionEndSocketTcti( tctiContext, 0 );

        CloseSockets( TCTI_CONTEXT_INTEL->otherSock, TCTI_CONTEXT_INTEL->tpmSock );

        free( tctiContext );
    }

    return rval;
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

    rval = CommonReceiveChecks( tctiContext, response_size, response_buffer );
    if( rval != TSS2_RC_SUCCESS )
    {
        goto retSocketReceiveTpmResponse;
    }        
    
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
        (*printfFunction)(NO_PREFIX, "select failed due to timeout, socket #: 0x%x\n", TCTI_CONTEXT_INTEL->tpmSock );
        rval = TSS2_TCTI_RC_TRY_AGAIN;
        goto retSocketReceiveTpmResponse;
    }
    else if( iResult == SOCKET_ERROR )
    {
        (*printfFunction)(NO_PREFIX, "select failed with socket error: %d\n", WSAGetLastError() );
        rval = TSS2_TCTI_RC_IO_ERROR;
        goto retSocketReceiveTpmResponse;
    }
    else if ( iResult != 1 )
    {
        (*printfFunction)(NO_PREFIX, "select failed, read the wrong # of bytes: %d\n", iResult );
        rval = TSS2_TCTI_RC_IO_ERROR;
        goto retSocketReceiveTpmResponse;
    }

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.protocolResponseSizeReceived != 1 )
    {        
        // Receive the size of the response.
        rval = recvBytes( TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)& (((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize ), 4 );
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
            if( TSS2_RC_SUCCESS != recvBytes( TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->tag ), 2 ) )
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
            if( TSS2_RC_SUCCESS != recvBytes( TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->responseSize ), 4 ) )
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
        if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED &&
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize > 0 )
        {
#ifdef DEBUG
            (*printfFunction)( rmDebugPrefix, "Response Received: " );
#endif
#ifdef DEBUG_SOCKETS
            (*printfFunction)( rmDebugPrefix, "from socket #0x%x:\n", TCTI_CONTEXT_INTEL->tpmSock );
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
        rval = recvBytes( TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)response_buffer, ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize - responseSizeDelta );
        if( rval != TSS2_RC_SUCCESS )
            goto retSocketReceiveTpmResponse;

#ifdef DEBUG
        if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED )
        {
            DEBUG_PRINT_BUFFER( response_buffer, ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize );
        }
#endif

        // Receive the appended four bytes of 0's
        rval = recvBytes( TCTI_CONTEXT_INTEL->tpmSock, (unsigned char *)&trash, 4 );
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

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED )
    {
//        (*printfFunction)(NO_PREFIX,  "%s sent cancel OFF command:\n", interfaceName );
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

TSS2_RC InitSocketTcti (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    size_t *contextSize,            // IN/OUT
    const TCTI_SOCKET_CONF *conf,              // IN
    const uint64_t magic,
    const uint32_t version,
	const char *interfaceName,
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
        (*printfFunction)(NO_PREFIX, "Initializing %s Interface\n", interfaceName );

        // Init TCTI context.
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->magic = magic;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->version = version;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->transmit = SocketSendTpmCommand;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->receive = SocketReceiveTpmResponse;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->finalize = SocketFinalize;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel = SocketCancel;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->getPollHandles = 0;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->setLocality = SocketSetLocality;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality = 3;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.rmDebugPrefix = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->currentTctiContext = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage = TCTI_STAGE_INITIALIZE;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.responseSizeReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.protocolResponseSizeReceived = 0;

        rval = (TSS2_RC) InitSockets( conf->hostname, conf->port, serverSockets, &otherSock, &tpmSock );
        if( rval == TSS2_RC_SUCCESS )
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->otherSock = otherSock;
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->tpmSock = tpmSock;
        }
        else
        {
            CloseSockets( otherSock, tpmSock);
        }            
    }

    return rval;
}

TSS2_RC TeardownSocketTcti (TSS2_TCTI_CONTEXT *tctiContext)
{
    ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->finalize( tctiContext );
  
    return TSS2_RC_SUCCESS;
}


