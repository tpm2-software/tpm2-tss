/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IFAPI_CONFIG_H
#define IFAPI_CONFIG_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tss2_tpm2_types.h"
#include "ifapi_io.h"

#define ENV_FAPI_CONFIG "TSS2_FAPICONF"

/**
 * Type for storing FAPI configuration
 */
typedef struct {
    /** Path for profile directory */
    char                *profile_dir;
    /** Directory storing NV objects */
    char                *user_dir;
    /** Directory storing key and NV objects */
    char                *keystore_dir;
    /** Name the used profile */
    char                *profile_name;
    /** The used tcti interface */
    char                *tcti;
    /** The directory for event logs */
    char                *log_dir;
    /** The PCRs used by IMA etc. */
    TPML_PCR_SELECTION  system_pcrs;
} IFAPI_CONFIG;

TSS2_RC
ifapi_config_initialize_async(
    IFAPI_IO            *io
        );

TSS2_RC
ifapi_config_initialize_finish(
    IFAPI_IO            *io,
    IFAPI_CONFIG        *config
    );

#endif /* IFAPI_CONFIG_H */
