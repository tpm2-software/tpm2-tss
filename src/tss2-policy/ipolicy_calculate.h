/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IPOLICY_CALCULATE_H
#define IPOLICY_CALCULATE_H

#include <stddef.h> // for size_t

#include "ipolicy_types.h"   // for TPML_POLICYELEMENTS
#include "tss2_common.h"     // for TSS2_RC
#include "tss2_tpm2_types.h" // for TPMI_ALG_HASH, TPML_DIGEST_VALUES

TSS2_RC
ipolicy_calculate_policy(TPML_POLICYELEMENTS *policy,
                         TPML_DIGEST_VALUES  *policyDigests,
                         TPMI_ALG_HASH        hash_alg,
                         size_t               hash_size,
                         size_t               digest_idx);

#endif /* IPOLICY_CALCULATE_H */
