/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef IPOLICY_HELPERS_H
#define IPOLICY_HELPERS_H

#include "ipolicy_types.h"
#include "tss2_policy.h"

void cleanup_policy_element(TPMT_POLICYELEMENT *policy);
void cleanup_policy_elements(TPML_POLICYELEMENTS *policy);

TSS2_RC
ifapi_compute_policy_digest(const TPML_PCRVALUES *pcrs,
                            TPML_PCR_SELECTION   *pcr_selection,
                            TPMI_ALG_HASH         hash_alg,
                            TPM2B_DIGEST         *pcr_digest);

void ifapi_helper_init_policy_pcr_selections(TSS2_POLICY_PCR_SELECTION *selection,
                                             const TPMT_POLICYELEMENT  *element);

#endif /* IPOLICY_HELPERS_H */
