/***********************************************************************
 * Copyright (c) 2015 - 2017 Intel Corporation
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

/*
 * The context for TCTI implementations is on opaque
 * structure. There shall never be a definition of its content.
 * Implementation provide the size information to
 * applications via the initialize call.
 * This makes use of a compiler trick that allows type
 * checking of the pointer even though the type isn't
 * defined.
 *
 * The first field of a Context must be the common part
 * (see below).
 */
#ifndef TSS2_TCTI_UTIL_H
#define TSS2_TCTI_UTIL_H

#include <errno.h>
#include <sapi/tpm20.h>

#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
#include <sys/socket.h>
#define SOCKET int
#endif

#include "tcti/common.h"

#define TCTI_MAGIC   0x7e18e9defa8bc9e2ULL
#define TCTI_VERSION 0x1

#define TCTI_CONTEXT ((TSS2_TCTI_CONTEXT_COMMON_CURRENT *)(SYS_CONTEXT->tctiContext))

#define TPM_HEADER_SIZE (sizeof (TPM2_ST) + sizeof (UINT32) + sizeof (UINT32))

#define TEMP_RETRY(exp) \
({  int __ret; \
    do { \
        __ret = exp; \
    } while (__ret == -1 && errno == EINTR); \
    __ret; })

typedef struct {
    TPM2_ST tag;
    UINT32 size;
    UINT32 code;
} tpm_header_t;

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
        UINT32 reserved: 1; /* Used to be debugMsgEnabled which is deprecated */
        UINT32 locality: 8;
        UINT32 commandSent: 1;
        UINT32 tagReceived: 1;
        UINT32 responseSizeReceived: 1;
        UINT32 protocolResponseSizeReceived: 1;
    } status;

    /* Following two fields used to save partial response in case receive buffer's too small. */
    TPM2_ST tag;
    TPM2_RC responseSize;

    TSS2_TCTI_CONTEXT *currentTctiContext;

    /* Sockets if socket interface is being used. */
    SOCKET otherSock;
    SOCKET tpmSock;
    SOCKET currentConnectSock;

    /* File descriptor for device file if real TPM is being used. */
    int devFile;
    UINT8 previousStage;            /* Used to check for sequencing errors. */
    unsigned char responseBuffer[4096];
} TSS2_TCTI_CONTEXT_INTEL;

/*
 * This function is used to "up cast" the common TCTI interface type to the
 * private type used in the implementation. This is how we control access to
 * the data below the 'setLocality' function.
 */
static inline TSS2_TCTI_CONTEXT_INTEL*
tcti_context_intel_cast (TSS2_TCTI_CONTEXT *ctx)
{
    return (TSS2_TCTI_CONTEXT_INTEL*)ctx;
}
/*
 * This funciton performs common checks on the context structure. It should
 * be used by all externally facing TCTI functions before the context is used
 * as any of the private types.
 */
TSS2_RC tcti_common_checks (
    TSS2_TCTI_CONTEXT *tcti_context
    );
/*
 * This function performs common checks on the context structure and the
 * buffer passed into TCTI 'transmit' functions.
 */
TSS2_RC tcti_send_checks (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t           *command_buffer
    );
/*
 * This function performs common checks on the context structure, buffer and
 * size parameter passed to the TCTI 'receive' functions.
 */
TSS2_RC tcti_receive_checks (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t            *response_size,
    unsigned char     *response_buffer
    );
/*
 * Write 'size' bytes from 'buf' to file descriptor 'fd'. Additionally this
 * function will retry calls to the 'write' function when recoverable errors
 * are detected. This is currently limited to interrupted system calls and
 * short writes.
 */
ssize_t write_all (
    int fd,
    const uint8_t *buf,
    size_t size);

#endif
