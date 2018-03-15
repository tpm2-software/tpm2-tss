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

#ifndef TPMCLIENT_H
#define TPMCLIENT_H

#include "tss2_mu.h"
#include "tss2_sys.h"

#define TPMBUF_LEN 0x8000
#define GLOBAL_SYS_CONTEXT_SIZE 4096
#define INIT_SIMPLE_TPM2B_SIZE(type) (type).size = sizeof(type) - 2;

#ifdef __cplusplus
extern "C" {
#endif

#define YES 1
#define NO  0

void InitSysContextFailure();
UINT32 TpmHash( TPMI_ALG_HASH hashAlg, UINT16 size, BYTE *data, TPM2B_DIGEST *result );
UINT32 TpmHandleToName( TPM2_HANDLE handle, TPM2B_NAME *name );
TSS2_RC CompareSizedByteBuffer( TPM2B *buffer1, TPM2B *buffer2 );

extern TSS2_TCTI_CONTEXT *resMgrTctiContext;

TSS2_RC SocketSendTpmCommand(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    size_t             command_size,      /* in */
    uint8_t           *command_buffer     /* in */
    );

TSS2_RC SocketReceiveTpmResponse(
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    size_t          *response_size,     /* out */
    unsigned char   *response_buffer,    /* in */
    int32_t         timeout
    );

#ifdef __cplusplus
}
#endif

#endif

