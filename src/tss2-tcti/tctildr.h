/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2019, Intel Corporation
 * All rights reserved.
 */
#ifndef TCTILDR_H
#define TCTILDR_H

#include "tss2_tpm2_types.h"
#include "tss2_tcti.h"

#define TCTILDR_MAGIC 0xbc44a31ca74b4aafULL

typedef void* TSS2_TCTI_LIBRARY_HANDLE;
typedef struct {
    TSS2_TCTI_CONTEXT_COMMON_V2 v2;
    TSS2_TCTI_LIBRARY_HANDLE library_handle;
    TSS2_TCTI_CONTEXT *tcti;
} TSS2_TCTILDR_CONTEXT;

TSS2_RC
tcti_from_init(TSS2_TCTI_INIT_FUNC init,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti);
TSS2_RC
tcti_from_info(TSS2_TCTI_INFO_FUNC infof,
               const char* conf,
               TSS2_TCTI_CONTEXT **tcti);
TSS2_RC
tctildr_transmit (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer);
TSS2_RC
tctildr_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout);
void
tctildr_finalize (
    TSS2_TCTI_CONTEXT *tctiContext);
TSS2_RC
tctildr_cancel (
    TSS2_TCTI_CONTEXT *tctiContext);
TSS2_RC
tctildr_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles);
TSS2_RC
tctildr_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality);
TSS2_RC
tctildr_make_sticky (
    TSS2_TCTI_CONTEXT *tctiContext,
    TPM2_HANDLE *handle,
    uint8_t sticky);

#endif /* TCTILDR_H */
