/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2019, Fraunhofer SIT, Infineon Technologies AG, Intel Corporation
 * All rights reserved.
 ******************************************************************************/

#ifndef TCTI_LIBTPMS_H
#define TCTI_LIBTPMS_H

#include <libtpms/tpm_library.h>  // for TPMLIB_StateType, TPMLIB_TPMVersion
#include <libtpms/tpm_types.h>    // for TPM_RESULT
#include <stdint.h>               // for uint32_t, uint8_t
#include <sys/mman.h>             // for size_t

#include "tcti-common.h"          // for TSS2_TCTI_COMMON_CONTEXT

#define TCTI_LIBTPMS_MAGIC 0x49E299A554504D32ULL

#define STATE_MMAP_CHUNK_LEN 2048

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    void *libtpms;
    TPM_RESULT (*TPMLIB_ChooseTPMVersion)(TPMLIB_TPMVersion);
    TPM_RESULT (*TPMLIB_RegisterCallbacks)(struct libtpms_callbacks *);
    TPM_RESULT (*TPMLIB_GetState)(enum TPMLIB_StateType, unsigned char **, uint32_t *);
    TPM_RESULT (*TPMLIB_MainInit)(void);
    TPM_RESULT (*TPMLIB_Process)(unsigned char **, uint32_t *, uint32_t *, unsigned char *, uint32_t);
    TPM_RESULT (*TPMLIB_SetState)(enum TPMLIB_StateType, const unsigned char *, uint32_t);
    void (*TPMLIB_Terminate)(void);
    TPM_RESULT (*TPM_IO_TpmEstablished_Reset)(void);
    uint8_t *response_buffer;
    size_t response_buffer_len;
    size_t response_len;
    char *state_path;
    bool state_is_thread_shared;
    char *state_mmap;
    size_t state_mmap_len;
    size_t state_len;
} TSS2_TCTI_LIBTPMS_CONTEXT;

#endif /* TCTI_LIBTPMS_H */
