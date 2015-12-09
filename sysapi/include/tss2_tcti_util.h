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
// The context for TCTI implementations is on opaque
// structure. There shall never be a definition of its content.
// Implementation provide the size information to
// applications via the initialize call.
// This makes use of a compiler trick that allows type
// checking of the pointer even though the type isn't
// defined.
//
// The first field of a Context must be the common part
// (see below). 
#ifndef TSS2_TCTI_UTIL_H
#define TSS2_TCTI_UTIL_H

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files !
#endif  /* TSS2_API_VERSION_1_1_1_1 */

#if defined linux || defined unix
#include <sys/socket.h>
#define SOCKET int
#endif

typedef TSS2_RC (*TCTI_TRANSMIT_PTR)( TSS2_TCTI_CONTEXT *tctiContext, size_t size, uint8_t *command);
typedef TSS2_RC (*TCTI_RECEIVE_PTR) (TSS2_TCTI_CONTEXT *tctiContext, size_t *size, uint8_t *response, int32_t timeout);

enum tctiStates { TCTI_STAGE_INITIALIZE, TCTI_STAGE_SEND_COMMAND, TCTI_STAGE_RECEIVE_RESPONSE };

/* current Intel version */
typedef struct {
    uint64_t magic;
    uint32_t version;
    TCTI_TRANSMIT_PTR transmit;
    TCTI_RECEIVE_PTR receive;
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext, 
              TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
    struct {
        UINT32 debugMsgLevel: 8;
        UINT32 locality: 8;
        UINT32 commandSent: 1;
        UINT32 rmDebugPrefix: 1;  // Used to add a prefix to RM debug messages.

        // Following two fields used to save partial response status in case receive buffer's too small.
        UINT32 tagReceived: 1;
        UINT32 responseSizeReceived: 1;
        UINT32 protocolResponseSizeReceived: 1;
    } status;

    // Following two fields used to save partial response in case receive buffer's too small.
    TPM_ST tag;         
    TPM_RC responseSize;
    
    TSS2_TCTI_CONTEXT *currentTctiContext;

    // Sockets if socket interface is being used.
    SOCKET otherSock;
    SOCKET tpmSock;
    SOCKET currentConnectSock;

    // File descriptor for device file if real TPM is being used.
    int devFile;  
    UINT8 previousStage;            // Used to check for sequencing errors.
    unsigned char responseBuffer[4096];
} TSS2_TCTI_CONTEXT_INTEL;

#define TCTI_CONTEXT ( (TSS2_TCTI_CONTEXT_COMMON_CURRENT *)(SYS_CONTEXT->tctiContext) )
#define TCTI_CONTEXT_INTEL ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )

typedef TSS2_RC (*TSS2_TCTI_INITIALIZE_FUNC) (
    // Buffer allocated by caller to contain
    // common part of context information.
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    // If tctiContext==NULL writes required size
    // to this variable. Otherwise expects the
    // size allocated for context.
    //
    // Pass NULL to retrieve required size
    // as return value.
    size_t *contextSize,            // IN/OUT
    // String that determines the configuration
    // to operate in (e.g. device-path,
    // remote-server-address, config-file-path).
    const char *config,             // IN        
    const uint64_t magic,
    const uint32_t version,
    const char *interfaceName,
    const uint8_t serverSockets
    );

typedef TSS2_RC (*TSS2_TCTI_TEARDOWN_FUNC) (
    // Buffer allocated by caller to contain
    // common part of context information.
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    // String that determines the configuration
    // to operate in (e.g. device-path,
    // remote-server-address, config-file-path).
    const char *config,              // IN
    const char *interfaceName    
    );

typedef struct {
    // Short-Name of the driver.
    const char *shortName;
    // Help-String for the driver, to be given
    // to the users.
    const char *helpString;
    // Pointer to an initialize function
    // for this mode.
    TSS2_TCTI_INITIALIZE_FUNC initialize; 
    TSS2_TCTI_TEARDOWN_FUNC teardown;
} TSS2_TCTI_DRIVER_INFO;


// TCTI debug message levels
#define TSS2_TCTI_DEBUG_MSG_DISABLED 0
#define TSS2_TCTI_DEBUG_MSG_ENABLED 1

#endif
