/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IFAPI_POLICY_H
#define IFAPI_POLICY_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include <json-c/json_util.h>

#include "tss2_esys.h"
#include "tss2_fapi.h"
#include "fapi_int.h"
#include "fapi_policy.h"

TSS2_RC
get_policy_digest_idx(
    TPML_DIGEST_VALUES *digest_values,
    TPMI_ALG_HASH hashAlg,
    size_t *idx);

TSS2_RC
ifapi_compute_policy_digest(
    TPML_PCRVALUES *pcrs,
    TPML_PCR_SELECTION *pcr_selection,
    TPMI_ALG_HASH hash_alg,
    TPM2B_DIGEST *pcr_digest);

TSS2_RC
ifapi_calculate_tree(
    FAPI_CONTEXT *context,
    const char *policyPath,
    TPMS_POLICY_HARNESS *harness,
    TPMI_ALG_HASH hash_alg,
    size_t *digest_idx,
    size_t *hash_size);

TSS2_RC
ifapi_calculate_policy_for_key(
    FAPI_CONTEXT *context,
    const char *policyPath,
    IFAPI_KEY_TEMPLATE *template,
    TPMS_POLICY_HARNESS **policy_harness);

#endif /* IFAPI_POLICY_H */
