/***********************************************************************
 * Copyright (c) 2015 - 2018 Intel Corporation
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
#ifndef TCTI_COMMON_H
#define TCTI_COMMON_H

#include <errno.h>
#include <stdbool.h>

#include "tss2_tcti.h"

#define TCTI_VERSION 0x2

#define TPM_HEADER_SIZE (sizeof (TPM2_ST) + sizeof (UINT32) + sizeof (UINT32))

typedef struct {
    TPM2_ST tag;
    UINT32 size;
    UINT32 code;
} tpm_header_t;
/*
 * The elements in this enumeration represent the possible states that the
 * TCTI can be in. The state machine is as follows:
 * An instantiated TCTI context begins in the TRANSMIT state:
 *   TRANSMIT:
 *     transmit:    success transitions the state machine to RECEIVE
 *                  failure leaves the state unchanged
 *     receive:     produces TSS2_TCTI_RC_BAD_SEQUENCE
 *     finalize:    transitions state machine to FINAL state
 *     cancel:      produces TSS2_TCTI_RC_BAD_SEQUENCE
 *     setLocality: success or failure leaves state unchanged
 *   RECEIVE:
 *     transmit:    produces TSS2_TCTI_RC_BAD_SEQUENCE
 *     receive:     success transitions the state machine to TRANSMIT
 *                  failure with the following RCs leave the state unchanged:
 *                    TRY_AGAIN, INSUFFICIENT_BUFFER, BAD_CONTEXT,
 *                    BAD_REFERENCE, BAD_VALUE, BAD_SEQUENCE
 *                  all other failures transition state machine to
 *                    TRANSMIT (not recoverable)
 *     finalize:    transitions state machine to FINAL state
 *     cancel:      success transitions state machine to TRANSMIT
 *                  failure leaves state unchanged
 *     setLocality: produces TSS2_TCTI_RC_BAD_SEQUENCE
 *   FINAL:
 *     all function calls produce TSS2_TCTI_RC_BAD_SEQUENCE
 */
typedef enum {
    TCTI_STATE_FINAL,
    TCTI_STATE_TRANSMIT,
    TCTI_STATE_RECEIVE,
} tcti_state_t;

typedef struct {
    TSS2_TCTI_CONTEXT_COMMON_V2 v2;
    tcti_state_t state;
    tpm_header_t header;
    uint8_t locality;
} TSS2_TCTI_COMMON_CONTEXT;

/*
 */
TSS2_TCTI_COMMON_CONTEXT*
tcti_common_context_cast (TSS2_TCTI_CONTEXT *ctx);
/*
 * This function is used to "down cast" the Intel TCTI context to the opaque
 * context type.
 */
TSS2_TCTI_CONTEXT*
tcti_common_down_cast (TSS2_TCTI_COMMON_CONTEXT *ctx);
/*
 * This function performs checks on the common context structure passed to a
 * TCTI 'cancel' function.
 */
TSS2_RC
tcti_common_cancel_checks (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common);
/*
 * This function performs common checks on the context structure and the
 * buffer passed into TCTI 'transmit' functions.
 */
TSS2_RC
tcti_common_transmit_checks (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common,
    const uint8_t *command_buffer);
/*
 * This function performs common checks on the context structure, buffer and
 * size parameter passed to the TCTI 'receive' functions.
 */
TSS2_RC
tcti_common_receive_checks (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common,
    size_t *response_size);
/*
 * This function performs checks on the common context structure passed to a
 * TCTI 'set_locality' function.
 */
TSS2_RC
tcti_common_set_locality_checks (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common);
/*
 * Just a function with the right prototype that returns the not implemented
 * RC for the TCTI layer.
 */
TSS2_RC
tcti_make_sticky_not_implemented (
    TSS2_TCTI_CONTEXT *tctiContext,
    TPM2_HANDLE *handle,
    uint8_t sticky);
/*
 * Utility to function to parse the first 10 bytes of a buffer and populate
 * the 'header' structure with the results. The provided buffer is assumed to
 * be at least 10 bytes long.
 */
TSS2_RC
header_unmarshal (
    const uint8_t *buf,
    tpm_header_t *header);
/*
 */
TSS2_RC
header_marshal (
    const tpm_header_t *header,
    uint8_t *buf);

#endif
