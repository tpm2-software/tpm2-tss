/*
 * Copyright (c) 2015 - 2018, Intel Corporation
 *
 * Copyright 2015, Andreas Fuchs @ Fraunhofer SIT
 *
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
 */
#ifndef TSS2_TCTI_H
#define TSS2_TCTI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "tss2_common.h"
#include "tss2_tpm2_types.h"

#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
#include <poll.h>
typedef struct pollfd TSS2_TCTI_POLL_HANDLE;
#elif defined(_WIN32)
#include <windows.h>
typedef HANDLE TSS2_TCTI_POLL_HANDLE;
#else
typedef void TSS2_TCTI_POLL_HANDLE;
#ifndef TSS2_TCTI_SUPPRESS_POLL_WARNINGS
#pragma message "Info: Platform not supported for TCTI_POLL_HANDLES"
#endif
#endif

/* The following are used to configure timeout characteristics. */
#define  TSS2_TCTI_TIMEOUT_BLOCK    -1
#define  TSS2_TCTI_TIMEOUT_NONE     0

/* Macros to simplify access to values in common TCTI structure */
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

/* Macros to simplify invocation of functions from the common TCTI structure */
#define Tss2_Tcti_Transmit(tctiContext, size, command) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_TRANSMIT(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_TRANSMIT(tctiContext)(tctiContext, size, command))
#define Tss2_Tcti_Receive(tctiContext, size, response, timeout) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_RECEIVE(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_RECEIVE(tctiContext)(tctiContext, size, response, timeout))
#define Tss2_Tcti_Finalize(tctiContext) \
    do { \
        if ((tctiContext != NULL) && \
            (TSS2_TCTI_VERSION(tctiContext) >= 1) && \
            (TSS2_TCTI_FINALIZE(tctiContext) != NULL)) \
        { \
            TSS2_TCTI_FINALIZE(tctiContext)(tctiContext); \
        } \
    } while (0)
#define Tss2_Tcti_Cancel(tctiContext) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_CANCEL(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_CANCEL(tctiContext)(tctiContext))
#define Tss2_Tcti_GetPollHandles(tctiContext, handles, num_handles) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_GET_POLL_HANDLES(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_GET_POLL_HANDLES(tctiContext)(tctiContext, handles, num_handles))
#define Tss2_Tcti_SetLocality(tctiContext, locality) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
    (TSS2_TCTI_VERSION(tctiContext) < 1) ? \
        TSS2_TCTI_RC_ABI_MISMATCH: \
    (TSS2_TCTI_SET_LOCALITY(tctiContext) == NULL) ? \
        TSS2_TCTI_RC_NOT_IMPLEMENTED: \
    TSS2_TCTI_SET_LOCALITY(tctiContext)(tctiContext, locality))

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
    TSS2_RC (*transmit) (TSS2_TCTI_CONTEXT *tctiContext,
                         size_t size,
                         const uint8_t *command);
    TSS2_RC (*receive) (TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
uint8_t *response, int32_t timeout);
    void (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
} TSS2_TCTI_CONTEXT_COMMON_V1;

typedef TSS2_TCTI_CONTEXT_COMMON_V1 TSS2_TCTI_CONTEXT_COMMON_CURRENT;

#define TSS2_TCTI_INFO_SYMBOL "Tss2_Tcti_Info"

typedef TSS2_RC (*TSS2_TCTI_INIT_FUNC) (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *config
    );

typedef struct {
    const char *name;
    const char *description;
    const char *config_help;
    TSS2_TCTI_INIT_FUNC init;
} TSS2_TCTI_INFO;

typedef const TSS2_TCTI_INFO* (*TSS2_TCTI_INFO_FUNC) (void);

#ifdef __cplusplus
}
#endif

#endif
