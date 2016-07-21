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

#ifndef TSS2_SYS_H
#define TSS2_SYS_H

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files. \
       Do not include this file, #include <sapi/tpm20.h> instead.
#endif  /* TSS2_API_VERSION_1_1_1_1 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sapi/tss2_tcti.h>

// Fields for ABI negotiation.
#define TSSWG_INTEROP 1
#define MAX_NON_VENDOR_SPECIFIC 0x20000000
#define TSS_SAPI_FIRST_FAMILY 1
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 1

//
// SAPI context blob.
//
typedef struct _TSS2_SYS_OPAQUE_CONTEXT_BLOB TSS2_SYS_CONTEXT;

//
// Input structure for authorization area(s).
//
typedef struct {
    uint8_t cmdAuthsCount;
    TPMS_AUTH_COMMAND **cmdAuths;
} TSS2_SYS_CMD_AUTHS;

//
// Output structure for authorization area(s).
//
typedef struct {
    uint8_t rspAuthsCount;
    TPMS_AUTH_RESPONSE **rspAuths;
} TSS2_SYS_RSP_AUTHS;


//
// SAPI data types
//

//
// SAPI management functions, e.g. Part 3
// Command-Independent functions.
//

//
// Command Context Allocation and
// De-Allocation Functions
//
size_t  Tss2_Sys_GetContextSize(
    size_t maxCommandResponseSize
    );

TSS2_RC Tss2_Sys_Initialize(
    TSS2_SYS_CONTEXT *sysContext,
    size_t contextSize,
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_ABI_VERSION *abiVersion
    );

void Tss2_Sys_Finalize(
    TSS2_SYS_CONTEXT *sysContext
    );

TSS2_RC Tss2_Sys_GetTctiContext(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_TCTI_CONTEXT **tctiContext
    );

//
// Command Preparation Functions
//
TSS2_RC Tss2_Sys_GetDecryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t *decryptParamSize,
    const uint8_t **decryptParamBuffer
    );

TSS2_RC Tss2_Sys_SetDecryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t decryptParamSize,
    const uint8_t *decryptParamBuffer
    );

TPM_RC Tss2_Sys_GetCpBuffer(
    TSS2_SYS_CONTEXT *sysContext,
    size_t *cpBufferUsedSize,
    const uint8_t **cpBuffer);

TPM_RC Tss2_Sys_SetCmdAuths(
    TSS2_SYS_CONTEXT * sysContext,
    const TSS2_SYS_CMD_AUTHS *cmdAuthsArray
    );


//
// Command Execution Functions
//
TSS2_RC Tss2_Sys_ExecuteAsync(
    TSS2_SYS_CONTEXT *sysContext
    );

TSS2_RC Tss2_Sys_ExecuteFinish(
    TSS2_SYS_CONTEXT *sysContext,
    int32_t timeout
    );

TSS2_RC Tss2_Sys_Execute(
    TSS2_SYS_CONTEXT *sysContext
    );

//
// Command Completion functions:
//
TSS2_RC Tss2_Sys_GetCommandCode(
    TSS2_SYS_CONTEXT *sysContext,
    UINT8 (*commandCode)[4]
    );

TSS2_RC Tss2_Sys_GetRspAuths(
    TSS2_SYS_CONTEXT *sysContext,
    TSS2_SYS_RSP_AUTHS *rspAuthsArray
    );

TSS2_RC Tss2_Sys_GetEncryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t *encryptParamSize,
    const uint8_t **encryptParamBuffer
    );

TSS2_RC Tss2_Sys_SetEncryptParam(
    TSS2_SYS_CONTEXT *sysContext,
    size_t encryptParamSize,
    const uint8_t *encryptParamBuffer
    );

TPM_RC Tss2_Sys_GetRpBuffer(
    TSS2_SYS_CONTEXT *sysContext,
    size_t *rpBufferUsedSize,
    const uint8_t **rpBuffer
    );

#include "sys_api_part3.h"

#ifdef __cplusplus
}
#endif

#endif
