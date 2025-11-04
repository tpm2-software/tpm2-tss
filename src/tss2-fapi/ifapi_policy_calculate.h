/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef FAPI_POLICY_CALCULATE_H
#define FAPI_POLICY_CALCULATE_H


#include <stddef.h>              // for size_t

#include "ifapi_policy_types.h"  // for TPML_POLICYELEMENTS
#include "tss2_common.h"         // for TSS2_RC
#include "tss2_tpm2_types.h"     // for TPMI_ALG_HASH, TPML_DIGEST_VALUES
//#include "fapi_policy.h"
//#include "ifapi_keystore.h"

TSS2_RC
ifapi_calculate_policy(
    TPML_POLICYELEMENTS *policy,
    TPML_DIGEST_VALUES *policyDigests,
    TPMI_ALG_HASH hash_alg,
    size_t hash_size,
    size_t digest_idx);

#endif /* FAPI_POLICY_CALCULATE_H */
