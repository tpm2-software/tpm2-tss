/*
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
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"

#include "tcti-common.h"
#define LOGMODULE tcti
#include "util/log.h"

TSS2_TCTI_COMMON_CONTEXT*
tcti_common_context_cast (TSS2_TCTI_CONTEXT *ctx)
{
    return (TSS2_TCTI_COMMON_CONTEXT*)ctx;
}

TSS2_TCTI_CONTEXT*
tcti_common_down_cast (TSS2_TCTI_COMMON_CONTEXT *ctx)
{
    return (TSS2_TCTI_CONTEXT*)&ctx->v2;
}

TSS2_RC
tcti_common_cancel_checks (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common)
{
    if (tcti_common->state != TCTI_STATE_RECEIVE) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_common_transmit_checks (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common,
    const uint8_t *command_buffer)
{
    if (tcti_common->state != TCTI_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    if (command_buffer == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_common_receive_checks (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common,
    size_t *response_size)
{
    if (tcti_common->state != TCTI_STATE_RECEIVE) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    if (response_size == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_common_set_locality_checks (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common)
{
    if (tcti_common->state != TCTI_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_make_sticky_not_implemented (
    TSS2_TCTI_CONTEXT *tctiContext,
    TPM2_HANDLE *handle,
    uint8_t sticky)
{
    (void)(tctiContext);
    (void)(handle);
    (void)(sticky);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
header_unmarshal (
    const uint8_t *buf,
    tpm_header_t *header)
{
    TSS2_RC rc;
    size_t offset = 0;

    LOG_TRACE ("Parsing header from buffer: 0x%" PRIxPTR, (uintptr_t)buf);
    rc = Tss2_MU_TPM2_ST_Unmarshal (buf,
                                    TPM_HEADER_SIZE,
                                    &offset,
                                    &header->tag);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to unmarshal tag.");
        return rc;
    }
    rc = Tss2_MU_UINT32_Unmarshal (buf,
                                   TPM_HEADER_SIZE,
                                   &offset,
                                   &header->size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to unmarshal command size.");
        return rc;
    }
    rc = Tss2_MU_UINT32_Unmarshal (buf,
                                   TPM_HEADER_SIZE,
                                   &offset,
                                   &header->code);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to unmarshal command code.");
    }
    return rc;
}

TSS2_RC
header_marshal (
    const tpm_header_t *header,
    uint8_t *buf)
{
    TSS2_RC rc;
    size_t offset = 0;

    LOG_TRACE ("Parsing header from buffer: 0x%" PRIxPTR, (uintptr_t)buf);
    rc = Tss2_MU_TPM2_ST_Marshal (header->tag,
                                  buf,
                                  TPM_HEADER_SIZE,
                                  &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to marshal tag.");
        return rc;
    }
    rc = Tss2_MU_UINT32_Marshal (header->size,
                                 buf,
                                 TPM_HEADER_SIZE,
                                 &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to marshal command size.");
        return rc;
    }
    rc = Tss2_MU_UINT32_Marshal (header->code,
                                 buf,
                                 TPM_HEADER_SIZE,
                                 &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed to marshal command code.");
    }
    return rc;
}
