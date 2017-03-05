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
#include <unistd.h>

#include "sapi/tpm20.h"
//#include "resourcemgr.h"
//#include <sample.h>
#include "sysapi_util.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "common/debug.h"
#include "commonchecks.h"
#include "tcti/tcti_device.h"
#include "logging.h"

#define HOSTNAME_LENGTH 200

const char *deviceTctiName = "device TCTI";

TSS2_RC LocalTpmSendTpmCommand(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    size_t             command_size,      /* in */
    uint8_t           *command_buffer     /* in */
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    ssize_t size;

#ifdef DEBUG
    UINT32 commandCode;
    UINT32 cnt;
#endif
    printf_type rmPrefix;

    rval = CommonSendChecks( tctiContext, command_buffer );

    if( rval == TSS2_RC_SUCCESS )
    {
        if( ( ( TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.rmDebugPrefix == 1 )
            rmPrefix = RM_PREFIX;
        else
            rmPrefix = NO_PREFIX;

#ifdef DEBUG
        commandCode = CHANGE_ENDIAN_DWORD( ( (TPM20_Header_In *)command_buffer )->commandCode );
        cnt = CHANGE_ENDIAN_DWORD(((TPM20_Header_In *) command_buffer)->commandSize);

        if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgEnabled == 1 )
        {
            TCTI_LOG( tctiContext, rmPrefix, "" );
            TCTI_LOG( tctiContext, rmPrefix, "Cmd sent: %s\n", strTpmCommandCode( commandCode ) );
            DEBUG_PRINT_BUFFER( rmPrefix, command_buffer, cnt );
        }
#endif

        size = write( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile, command_buffer, command_size );

        if( size < 0 )
        {
            TCTI_LOG( tctiContext, rmPrefix, "send failed with error: %d\n", errno );
            rval = TSS2_TCTI_RC_IO_ERROR;
        }
        else if( (size_t)size != command_size )
        {
            rval = TSS2_TCTI_RC_IO_ERROR;
        }

        if( rval == TSS2_RC_SUCCESS )
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage = TCTI_STAGE_SEND_COMMAND;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.responseSizeReceived = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.protocolResponseSizeReceived = 0;

        }
    }

    return rval;
}

TSS2_RC LocalTpmReceiveTpmResponse(
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    size_t          *response_size,     /* out */
    unsigned char   *response_buffer,    /* in */
    int32_t         timeout
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    ssize_t  size;
    unsigned int i;
    printf_type rmPrefix;

    rval = CommonReceiveChecks( tctiContext, response_size, response_buffer );
    if( rval != TSS2_RC_SUCCESS )
    {
        goto retLocalTpmReceive;
    }

    if( ( ( TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.rmDebugPrefix == 1 )
        rmPrefix = RM_PREFIX;
    else
        rmPrefix = NO_PREFIX;

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived == 0 )
    {
        size = read( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile, &((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseBuffer[0], 4096 );

        if( size < 0 )
        {
            TCTI_LOG( tctiContext, rmPrefix, "read failed with error: %d\n", errno );
            rval = TSS2_TCTI_RC_IO_ERROR;
            goto retLocalTpmReceive;
        }
        else
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived = 1;
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize = size;
        }

        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize = size;
    }

    if( response_buffer == NULL )
    {
        // In this case, just return the size
        *response_size = ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize;
        goto retLocalTpmReceive;
    }

    if( *response_size < ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize )
    {
        rval = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        *response_size = ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize;
        goto retLocalTpmReceive;
    }

    *response_size = ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize;

    for( i = 0; i < *response_size; i++ )
    {
        response_buffer[i] = ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseBuffer[i];
    }

#ifdef DEBUG
    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgEnabled == 1 &&
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize > 0 )
    {
        TCTI_LOG( tctiContext, rmPrefix, "\n" );
        TCTI_LOG( tctiContext, rmPrefix, "Response Received: " );
        DEBUG_PRINT_BUFFER( rmPrefix, response_buffer, ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize );
    }
#endif

    ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 0;

retLocalTpmReceive:

    if( rval == TSS2_RC_SUCCESS &&
		response_buffer != NULL )
    {
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage = TCTI_STAGE_RECEIVE_RESPONSE;
    }

    return rval;
}

void LocalTpmFinalize(
    TSS2_TCTI_CONTEXT *tctiContext       /* in */
    )
{
    if( tctiContext != NULL )
    {
        close( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile );
    }
}

TSS2_RC LocalTpmCancel(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    // TBD.  Needs support from device driver.

    return rval;
}

TSS2_RC LocalTpmSetLocality(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    uint8_t           locality     /* in */
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    // TBD:  how do I do this?

    return rval;
}

TSS2_RC InitDeviceTcti (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    size_t *contextSize,            // IN/OUT
    const TCTI_DEVICE_CONF *config  // IN
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( tctiContext == NULL && contextSize == NULL )
        return TSS2_TCTI_RC_BAD_VALUE;
    if( tctiContext == NULL )
    {
        *contextSize = sizeof( TSS2_TCTI_CONTEXT_INTEL );
        return TSS2_RC_SUCCESS;
    }
    else if( config == NULL )
    {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    else
    {
        // Init TCTI context.
        TSS2_TCTI_MAGIC( tctiContext ) = TCTI_MAGIC;
        TSS2_TCTI_VERSION( tctiContext ) = TCTI_VERSION;
        TSS2_TCTI_TRANSMIT( tctiContext ) = LocalTpmSendTpmCommand;
        TSS2_TCTI_RECEIVE( tctiContext ) = LocalTpmReceiveTpmResponse;
        TSS2_TCTI_FINALIZE( tctiContext ) = LocalTpmFinalize;
        TSS2_TCTI_CANCEL( tctiContext ) = LocalTpmCancel;
        TSS2_TCTI_GET_POLL_HANDLES( tctiContext ) = 0;
        TSS2_TCTI_SET_LOCALITY( tctiContext ) = LocalTpmSetLocality;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality = 3;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.rmDebugPrefix = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->currentTctiContext = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage = TCTI_STAGE_INITIALIZE;
        TCTI_LOG_CALLBACK( tctiContext ) = config->logCallback;
        TCTI_LOG_DATA( tctiContext ) = config->logData;

        ( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile ) = open( config->device_path, O_RDWR );
        if( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile < 0 )
        {
            return( TSS2_TCTI_RC_IO_ERROR );
        }
    }

    return rval;
}
