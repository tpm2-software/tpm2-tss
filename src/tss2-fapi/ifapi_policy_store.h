/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifndef IFAPI_POLICY_STORE_H
#define IFAPI_POLICY_STORE_H

#include "ifapi_io.h"            // for IFAPI_IO
#include "ifapi_policy_types.h"  // for TPMS_POLICY
#include "tss2_common.h"         // for TSS2_RC

typedef struct IFAPI_POLICY_STORE {
    char *policydir;
} IFAPI_POLICY_STORE;

TSS2_RC
ifapi_policy_delete(
     IFAPI_POLICY_STORE *pstore,
     char *path);

TSS2_RC
ifapi_policy_store_initialize(
    IFAPI_POLICY_STORE *pstore,
    const char *config_policydir);

TSS2_RC
ifapi_policy_store_load_async(
    IFAPI_POLICY_STORE *pstore,
    IFAPI_IO *io,
    const char *path);

TSS2_RC
ifapi_policy_store_load_finish(
    IFAPI_POLICY_STORE *pstore,
    IFAPI_IO *io,
    TPMS_POLICY *policy);

TSS2_RC
ifapi_policy_store_store_async(
    IFAPI_POLICY_STORE *pstore,
    IFAPI_IO *io,
    const char *path,
    const TPMS_POLICY *policy);

TSS2_RC
ifapi_policy_store_store_finish(
    IFAPI_POLICY_STORE *pstore,
    IFAPI_IO *io);

TSS2_RC
ifapi_policystore_check_overwrite(
    IFAPI_POLICY_STORE *pstore,
    const char *path);

#endif /* IFAPI_POLICY_STORE_H */
