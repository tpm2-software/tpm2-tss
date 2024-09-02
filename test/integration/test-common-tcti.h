/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2024, Infineon Technologies AG
 *
 * All rights reserved.
 ***********************************************************************/
#ifndef TEST_COMMON_TCTI_H
#define TEST_COMMON_TCTI_H

#include <stddef.h>       // for size_t
#include <stdint.h>       // for uint32_t, uint8_t, int32_t, uint64_t

#include "tss2_common.h"  // for TSS2_RC
#include "tss2_tcti.h"    // for TSS2_TCTI_CONTEXT, TSS2_TCTI_POLL_HANDLE

enum TSS2_TCTI_CONTEXT_PROXY_STATE {
    forwarding,
    intercepting
};

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
              TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
    TSS2_TCTI_CONTEXT *tctiInner;
    enum TSS2_TCTI_CONTEXT_PROXY_STATE state;
} TSS2_TCTI_CONTEXT_PROXY;

typedef struct {
    unsigned char *permanent_buf;
    unsigned char *volatile_buf;
    uint32_t permanent_buf_len;
    uint32_t volatile_buf_len;
} libtpms_state;

TSS2_RC tcti_proxy_transmit(TSS2_TCTI_CONTEXT *tctiContext, size_t command_size, const uint8_t *command_buffer);
TSS2_RC tcti_proxy_receive(TSS2_TCTI_CONTEXT *tctiContext, size_t *response_size, uint8_t *response_buffer, int32_t timeout);
TSS2_RC tcti_proxy_initialize(TSS2_TCTI_CONTEXT *tctiContext, size_t *contextSize, TSS2_TCTI_CONTEXT *tctiInner);
void tcti_proxy_finalize(TSS2_TCTI_CONTEXT *tctiContext);

TSS2_TCTI_CONTEXT *tcti_unwrap(TSS2_TCTI_CONTEXT *tcti);
void tcti_dump(TSS2_TCTI_CONTEXT *tcti);
int tcti_is_volatile (TSS2_TCTI_CONTEXT *tcti);
int tcti_state_backup_supported (TSS2_TCTI_CONTEXT *tcti);
int tcti_state_backup(TSS2_TCTI_CONTEXT *tcti, libtpms_state *state);
int tcti_state_restore(TSS2_TCTI_CONTEXT *tcti, libtpms_state *state);
int tcti_state_backup_if_necessary(TSS2_TCTI_CONTEXT *tcti, libtpms_state *state);
int tcti_state_restore_if_necessary(TSS2_TCTI_CONTEXT *tcti, libtpms_state *state);
TSS2_RC tcti_reset_tpm(TSS2_TCTI_CONTEXT *tcti);

#endif  /* TEST_COMMON_TCTI_H */
