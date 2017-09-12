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

#ifndef TSS2_SYSAPI_UTIL_H
#define TSS2_SYSAPI_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sapi/tss_compiler.h>
#include "tcti_util.h"

// TBD:  delete this after porting completed.
#define CMD_STAGE_1     1

enum cmdStates { CMD_STAGE_INITIALIZE, CMD_STAGE_PREPARE, CMD_STAGE_SEND_COMMAND, CMD_STAGE_RECEIVE_RESPONSE, CMD_STAGE_ALL = 0xff };

typedef struct {
  TPM_ST  tag;
  UINT32  size;
  TPM_RC  rsp_code;
} PACKED TPM20_Rsp_Header;

typedef struct {
    //
    // These are inputs to system API functions.
    //
    TSS2_TCTI_CONTEXT *tctiContext;

    // In and out buffers can be the same for a minimalized memory footprint implementation.
    UINT8 *tpmInBuffPtr;            // Input: Pointer to command buffer area
    UINT32 maxCommandSize;          // Input: max size of command buffer area
    UINT8 *tpmOutBuffPtr;           // Input: Pointer to response buffer
    UINT32 maxResponseSize;         // Input: max size of response buffer area

    TPM20_Rsp_Header rsp_header;

    //
    // These are set by system API and used by helper functions to calculate cpHash,
    // rpHash, and for auditing.
    //
    TPM_CC commandCodeSwapped;
    UINT32 cpBufferUsedSize;
    UINT8 *cpBuffer;
    UINT32 *rspParamsSize;  // Points to response paramsSize.
    UINT32 rpBufferUsedSize;
    UINT8 *rpBuffer;
    UINT8 previousStage;            // Used to check for sequencing errors.
    UINT8 authsCount;
    UINT8 numResponseHandles;
    struct
    {
        UINT16 tpmVersionInfoValid:1;  // Identifies whether the TPM version info fields are valid; if not valid
                                      // this info can't be used for TPM version-specific workarounds.
        UINT16 decryptAllowed:1;  // Identifies whether this command supports an encrypted command parameter.
        UINT16 encryptAllowed:1;  // Identifies whether this command supports an encrypted response parameter.

        UINT16 decryptNull:1;     // Indicates that the decrypt param was NULL at _Prepare call.
        UINT16 authAllowed:1;

        // Following are used to support decrypt/encrypt sessions with one-call.
        UINT16 decryptSession:1; // If true, complex TPM2B's are not marshalled but instead treated as simple TPM2B's.
        UINT16 encryptSession:1; // If true, complex TPM2B's are not unmarshalled but instead treated as simple TPM2B's.
        UINT16 prepareCalledFromOneCall:1;    // Indicates that the _Prepare call was called from the one-call.
        UINT16 completeCalledFromOneCall:1;    // Indicates that the _Prepare call was called from the one-call.
    };

    // Used to maintain state of SAPI functions.

    // Placeholder for current rval.  This is a convenience and code size optimization for SAPI functions.
    // Marshalling functions check this and SAPI functions return it.
    TSS2_RC rval;

    // Location for next data in command/response buffer.
    UINT8 *nextData;

} _TSS2_SYS_CONTEXT_BLOB;


#define SYS_CONTEXT ( (_TSS2_SYS_CONTEXT_BLOB *)sysContext )

//
// Generic header
//
typedef struct _TPM20_Header_In {
  TPM_ST tag;
  UINT32 commandSize;
  UINT32 commandCode;
} PACKED TPM20_Header_In;

typedef struct _TPM20_Header_Out {
  TPM_ST tag;
  UINT32 responseSize;
  UINT32 responseCode;
  UINT8 otherData;
} PACKED TPM20_Header_Out;

typedef struct _TPM20_ErrorResponse {
  TPM_ST tag;
  UINT32 responseSize;
  UINT32 responseCode;
} PACKED TPM20_ErrorResponse;

typedef struct {
    TPM_CC commandCode;
    int numCommandHandles;  // Num of handles that require authorization in
                            // command: used for virtualization and for
                            // parsing sessions following handles section.
    int numResponseHandles; // Num of handles that require authorization in
                            // in response: used for virtualization and for
                            // parsing sessions following handles section.
} COMMAND_HANDLES;


// Utility functions.
void CopyCommandHeader( _TSS2_SYS_CONTEXT_BLOB *sysContext, TPM_CC commandCode );
TPM_RC FinishCommand( _TSS2_SYS_CONTEXT_BLOB *sysContext,
    const TSS2_SYS_CMD_AUTHS *cmdAuthsArray, UINT32 *responseSize );

UINT16 GetDigestSize( TPM_ALG_ID authHash );
UINT32 GetCommandSize( TSS2_SYS_CONTEXT *sysContext );
TSS2_RC CopySessionsDataIn( void **otherData, const TSS2_SYS_CMD_AUTHS *pSessionDataIn );
TSS2_RC CopySessionDataIn( void **otherData, TPMS_AUTH_COMMAND const *sessionData, UINT32 *sessionSizePtr );
TSS2_RC CopySessionDataOut( TPMS_AUTH_RESPONSE *sessionData, void **otherData, UINT8* outBuffPtr, UINT32 outBuffSize );
TSS2_RC CopySessionsDataOut( TSS2_SYS_RSP_AUTHS *rspAuthsArray, void *otherData, TPM_ST tag, UINT8* outBuffPtr, UINT32 outBuffSize );

TPM_RC ConcatSizedByteBuffer( TPM2B_MAX_BUFFER *result, TPM2B *addBuffer );

void InitSysContextFields( TSS2_SYS_CONTEXT *sysContext );
void InitSysContextPtrs ( TSS2_SYS_CONTEXT *sysContext, size_t contextSize );

TSS2_RC CompleteChecks( TSS2_SYS_CONTEXT *sysContext );

TSS2_RC CommonComplete( TSS2_SYS_CONTEXT *sysContext );

TSS2_RC  CommonOneCallForNoResponseCmds(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC CommonOneCall(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC CommonPreparePrologue(
    TSS2_SYS_CONTEXT *sysContext,
    TPM_CC commandCode
    );

TSS2_RC CommonPrepareEpilogue(
    TSS2_SYS_CONTEXT *sysContext
    );

TSS2_RC CopyMem( UINT8 *dest, const UINT8 *src, const size_t len, const UINT8 *limit );

TSS2_RC CopyMemReverse( UINT8 *dest, const UINT8 *src, const size_t len, const UINT8 *limit );

int GetNumCommandHandles( TPM_CC commandCode );

int GetNumResponseHandles( TPM_CC commandCode );

TSS2_SYS_CONTEXT *InitSysContext(
    UINT16 maxCommandSize,
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_ABI_VERSION *abiVersion
 );

void TeardownSysContext( TSS2_SYS_CONTEXT **sysContext );

#include "sys_api_marshalUnmarshal.h"

#ifdef __cplusplus
}
#endif

#endif  // TSS2_SYSAPI_UTIL_H
