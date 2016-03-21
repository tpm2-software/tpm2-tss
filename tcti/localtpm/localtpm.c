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

#include <tpm20.h>
//#include "resourcemgr.h"
//#include <sample.h>
#include <tss2_sysapi_util.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "debug.h"
#include "commonchecks.h"
#include "localtpm.h"

#ifdef  _WIN32
#define ssize_t int
#elif __linux
#include <unistd.h>
#endif

#define HOSTNAME_LENGTH 200

extern void OpenOutFile( FILE **outFp );

extern void CloseOutFile( FILE **outFp );

extern FILE *outFp;

#ifdef SAPI_CLIENT
extern int TpmClientPrintf( UINT8 type, const char *format, ... );
int (*tpmLocalTpmPrintf)( UINT8 type, const char *format, ...) = TpmClientPrintf;
#else
extern int ResMgrPrintf( UINT8 type, const char *format, ... );
int (*tpmLocalTpmPrintf)( UINT8 type, const char *format, ...) = ResMgrPrintf;
#endif

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
    
    rval = CommonSendChecks( tctiContext, command_buffer );

    if( rval == TSS2_RC_SUCCESS )
    {
#ifdef DEBUG
        commandCode = CHANGE_ENDIAN_DWORD( ( (TPM20_Header_In *)command_buffer )->commandCode );
        cnt = CHANGE_ENDIAN_DWORD(((TPM20_Header_In *) command_buffer)->commandSize);

        if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED )
        {
            (*tpmLocalTpmPrintf)( rmDebugPrefix, "\n" );
            (*tpmLocalTpmPrintf)(rmDebugPrefix, "Cmd sent: %s\n", commandCodeStrings[ commandCode - TPM_CC_FIRST ]  );
            DEBUG_PRINT_BUFFER( command_buffer, cnt );
        }
#endif

        size = write( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile, command_buffer, command_size );

        if( size < 0 )
        {
            (*tpmLocalTpmPrintf)(NO_PREFIX, "send failed with error: %d\n", errno );
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
    
    rval = CommonReceiveChecks( tctiContext, response_size, response_buffer );
    if( rval != TSS2_RC_SUCCESS )
    {
        goto retLocalTpmReceive;
    }        

    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.tagReceived == 0 )
    {
        size = read( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile, &((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseBuffer[0], 4096 );

        if( size < 0 )
        {
            (*tpmLocalTpmPrintf)(NO_PREFIX, "read failed with error: %d\n", errno );
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
    if( ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->status.debugMsgLevel == TSS2_TCTI_DEBUG_MSG_ENABLED &&
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize > 0 )
    {
        (*tpmLocalTpmPrintf)( rmDebugPrefix, "\n" );
        (*tpmLocalTpmPrintf)( rmDebugPrefix, "Response Received: " );
        DEBUG_PRINT_BUFFER( response_buffer, ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->responseSize );
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
    if( tctiContext != 0 )
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

TSS2_RC InitLocalTpmTcti (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    size_t *contextSize,            // IN/OUT
    const char *config,              // IN
    const uint64_t magic,
    const uint32_t version,
	const char *interfaceName,
    const uint8_t serverSockets  // Unused for local TPM.
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    char fileName[200];

    if( tctiContext == NULL )
    {
        *contextSize = sizeof( TSS2_TCTI_CONTEXT_INTEL );
        return TSS2_RC_SUCCESS;
    }
    else
    {
        OpenOutFile( &outFp );
        (*tpmLocalTpmPrintf)(NO_PREFIX, "Initializing %s Interface\n", interfaceName );

        // Init TCTI context.
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->magic = magic;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->version = version;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->transmit = LocalTpmSendTpmCommand;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->receive = LocalTpmReceiveTpmResponse;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->finalize = LocalTpmFinalize;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel = LocalTpmCancel;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->getPollHandles = 0;
        ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->setLocality = LocalTpmSetLocality;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality = 3;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.rmDebugPrefix = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->currentTctiContext = 0;
        ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->previousStage = TCTI_STAGE_INITIALIZE;

        // Get hostname and port.
        if( ( strlen( config ) + 2 ) <= ( HOSTNAME_LENGTH  ) )
        {
            if( 1 != sscanf( config, "%199s", fileName ) ) 
            {
                return( TSS2_TCTI_RC_BAD_VALUE );
            }
        }
        else
        {
            return( TSS2_TCTI_RC_INSUFFICIENT_BUFFER );
        }

        ( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile ) = open( fileName, O_RDWR );
        if( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )->devFile < 0 ) 
        {
            return( TSS2_TCTI_RC_IO_ERROR );
        }

        CloseOutFile( &outFp );
    }

    return rval;
}

TSS2_RC TeardownLocalTpmTcti (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    const char *config,              // IN        
	const char *interfaceName
    )
{
    OpenOutFile( &outFp );
    (*tpmLocalTpmPrintf)(NO_PREFIX, "Tearing down %s Interface\n", interfaceName );
    CloseOutFile( &outFp );

    ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->finalize( tctiContext );

  
    return TSS2_RC_SUCCESS;
}

char localTpmInterfaceConfig[LOCAL_INTERFACE_CONFIG_SIZE];
    
TSS2_TCTI_DRIVER_INFO localTpmInterfaceInfo = { "local TPM", "", InitLocalTpmTcti, TeardownLocalTpmTcti };

TSS2_RC InitLocalTpmTctiContext( const char *driverConfig, TSS2_TCTI_CONTEXT **tctiContext )
{
    size_t size;
    
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = localTpmInterfaceInfo.initialize(NULL, &size, driverConfig, 0, 0, localTpmInterfaceInfo.shortName, 1 );
    if( rval != TSS2_RC_SUCCESS )
        return rval;
    
    *tctiContext = malloc(size);

    rval = localTpmInterfaceInfo.initialize(*tctiContext, &size, driverConfig, TCTI_MAGIC, TCTI_VERSION, localTpmInterfaceInfo.shortName, 0 );
    return rval;
}

TSS2_RC TeardownLocalTpmTctiContext( const char *driverConfig, TSS2_TCTI_CONTEXT *tctiContext )
{
    TSS2_RC rval;

    rval = localTpmInterfaceInfo.teardown( tctiContext, driverConfig, localTpmInterfaceInfo.shortName );
    if( rval != TSS2_RC_SUCCESS )
        return rval;

    return rval;
}
