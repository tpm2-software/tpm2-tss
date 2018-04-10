/***********************************************************************;
 * Copyright (c) 2015 - 2018, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ***********************************************************************/

#ifndef TSS2_SYSAPI_UTIL_H
#define TSS2_SYSAPI_UTIL_H

#include "tss2_tpm2_types.h"
#include "tss2_tcti.h"
#include "tss2_sys.h"
#include "util/tpm2b.h"

enum cmdStates {CMD_STAGE_INITIALIZE,
                CMD_STAGE_PREPARE,
                CMD_STAGE_SEND_COMMAND,
                CMD_STAGE_RECEIVE_RESPONSE,
                CMD_STAGE_ALL = 0xff };

#pragma pack(push, 1)
typedef struct _TPM20_Header_In {
  TPM2_ST tag;
  UINT32 commandSize;
  UINT32 commandCode;
} TPM20_Header_In;

typedef struct _TPM20_Header_Out {
  TPM2_ST tag;
  UINT32 responseSize;
  UINT32 responseCode;
} TPM20_Header_Out;

typedef struct _TPM20_ErrorResponse {
  TPM2_ST tag;
  UINT32 responseSize;
  UINT32 responseCode;
} TPM20_ErrorResponse;
#pragma pack(pop)

typedef struct {
    TSS2_TCTI_CONTEXT *tctiContext;
    UINT8 *cmdBuffer;
    UINT32 maxCmdSize;
    TPM20_Header_Out rsp_header;

    TPM2_CC commandCode;    /* In host endian */
    UINT32 cpBufferUsedSize;
    UINT8 *cpBuffer;
    UINT32 *rspParamsSize;
    UINT8 previousStage;
    UINT8 authsCount;
    UINT8 numResponseHandles;

    struct
    {
        UINT16 decryptAllowed:1;
        UINT16 encryptAllowed:1;
        UINT16 decryptNull:1;
        UINT16 authAllowed:1;
    };

    /* Offset to next data in command/response buffer. */
    size_t nextData;
} _TSS2_SYS_CONTEXT_BLOB;

struct TSS2_SYS_CONTEXT;

static inline _TSS2_SYS_CONTEXT_BLOB *
syscontext_cast(TSS2_SYS_CONTEXT *ctx)
{
    return (_TSS2_SYS_CONTEXT_BLOB*) ctx;
}

static inline TPM20_Header_Out *
resp_header_from_cxt(_TSS2_SYS_CONTEXT_BLOB *ctx)
{
    return (TPM20_Header_Out *)ctx->cmdBuffer;
}

static inline TPM20_Header_In *
req_header_from_cxt(_TSS2_SYS_CONTEXT_BLOB *ctx)
{
    return (TPM20_Header_In *)ctx->cmdBuffer;
}

typedef struct {
    TPM2_CC commandCode;
    int numCommandHandles;
    int numResponseHandles;
} COMMAND_HANDLES;

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC CopyCommandHeader(_TSS2_SYS_CONTEXT_BLOB *ctx, TPM2_CC commandCode);
UINT32 GetCommandSize(_TSS2_SYS_CONTEXT_BLOB *ctx);
void InitSysContextFields(_TSS2_SYS_CONTEXT_BLOB *ctx);
void InitSysContextPtrs(_TSS2_SYS_CONTEXT_BLOB *ctx, size_t contextSize);
TSS2_RC CompleteChecks(_TSS2_SYS_CONTEXT_BLOB *ctx);
TSS2_RC CommonComplete(_TSS2_SYS_CONTEXT_BLOB *ctx);

TSS2_RC CommonOneCall(
    _TSS2_SYS_CONTEXT_BLOB *ctx,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC CommonPreparePrologue(
    _TSS2_SYS_CONTEXT_BLOB *ctx,
    TPM2_CC commandCode);

TSS2_RC CommonPrepareEpilogue(_TSS2_SYS_CONTEXT_BLOB *ctx);
int GetNumCommandHandles(TPM2_CC commandCode);
int GetNumResponseHandles(TPM2_CC commandCode);

TSS2_SYS_CONTEXT *InitSysContext(
    UINT16 maxCommandSize,
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_ABI_VERSION *abiVersion);

void TeardownSysContext(TSS2_SYS_CONTEXT **ctx);

#ifdef __cplusplus
}
#endif
#endif
