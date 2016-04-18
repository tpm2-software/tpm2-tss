//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
//
// Copyright 2015, Andreas Fuchs @ Fraunhofer SIT
//
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
#ifndef TSS2_TCTI
#define TSS2_TCTI

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files. \
       Do not include this file, #include <tss2/tpm20.h> instead.
#endif  /* TSS2_API_VERSION_1_1_1_1 */

#ifdef __cplusplus
extern "C" {
#endif

#include "tss2_common.h"
#include <stddef.h>

#if defined _WIN32
#include <winsock2.h>
#include <windows.h>
typedef HANDLE TSS2_TCTI_POLL_HANDLE;
#elif defined linux || defined unix
#include <poll.h>
typedef struct pollfd TSS2_TCTI_POLL_HANDLE;
#else
typedef void TSS2_TCTI_POLL_HANDLE;
#error Info: Platform not supported for TCTI_POLL_HANDLES
#endif

// The following are used to configure timeout characteristics.
#define  TSS2_TCTI_TIMEOUT_BLOCK    -1
#define  TSS2_TCTI_TIMEOUT_NONE     0

// Macros to simplify access to values in common TCTI structure
#define TSS2_TCTI_MAGIC(tctiContext) \
    ((TSS2_TCTI_CONTEXT_VERSION*)tctiContext)->magic
#define TSS2_TCTI_VERSION(tctiContext) \
    ((TSS2_TCTI_CONTEXT_VERSION*)tctiContext)->version
#define TSS2_TCTI_TRANSMIT(tctiContext) \
    ((TSS2_TCTI_CONTEXT_COMMON_V1*)tctiContext)->transmit
#define TSS2_TCTI_RECEIVE(tctiContext) \
    ((TSS2_TCTI_CONTEXT_COMMON_V1*)tctiContext)->receive
#define TSS2_TCTI_FINALIZE(tctiContext) \
    ((TSS2_TCTI_CONTEXT_COMMON_V1*)tctiContext)->finalize
#define TSS2_TCTI_CANCEL(tctiContext) \
    ((TSS2_TCTI_CONTEXT_COMMON_V1*)tctiContext)->cancel
#define TSS2_TCTI_GET_POLL_HANDLES(tctiContext) \
    ((TSS2_TCTI_CONTEXT_COMMON_V1*)tctiContext)->getPollHandles
#define TSS2_TCTI_SET_LOCALITY(tctiContext) \
    ((TSS2_TCTI_CONTEXT_COMMON_V1*)tctiContext)->setLocality

// Macros to simplify invocation of functions from the common TCTI structure
#define tss2_tcti_transmit(tctiContext, size, command) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_TRANSMIT(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_TRANSMIT(tctiContext)(tctiContext, size, command))
#define tss2_tcti_receive(tctiContext, size, command) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_RECEIVE(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_RECEIVE(tctiContext)(tctiContext, size, command))
#define tss2_tcti_finalize(tctiContext, size, command) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_FINALIZE(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_FINALIZE(tctiContext)(tctiContext, size, command))
#define tss2_tcti_cancel(tctiContext, size, command) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_CANCEL(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_CANCEL(tctiContext)(tctiContext, size, command))
#define tss2_tcti_get_poll_handles(tctiContext, size, command) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_GET_POLL_HANDLES(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_GET_POLL_HANDLES(tctiContext)(tctiContext, size, command))
#define tss2_tcti_set_locality(tctiContext, size, command) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_SET_LOCALITY(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_SET_LOCALITY(tctiContext)(tctiContext, size, command))

typedef struct TSS2_TCTI_OPAQUE_CONTEXT_BLOB TSS2_TCTI_CONTEXT;

/* superclass to get the version */
typedef struct {
    uint64_t magic;
    uint32_t version;
} TSS2_TCTI_CONTEXT_VERSION ;

/* current version #1 known to this implementation */
typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_RC (*transmit)( TSS2_TCTI_CONTEXT *tctiContext, size_t size,
uint8_t *command);
    TSS2_RC (*receive) (TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
uint8_t *response, int32_t timeout);
    void (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
} TSS2_TCTI_CONTEXT_COMMON_V1;

typedef TSS2_TCTI_CONTEXT_COMMON_V1 TSS2_TCTI_CONTEXT_COMMON_CURRENT;

#ifdef __cplusplus
}
#endif

#endif
