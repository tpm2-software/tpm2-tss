/* SPDX-FileCopyrightText: 2026, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef IPOLICY_HELPERS_H
#define IPOLICY_HELPERS_H

#include "ipolicy_types.h"
#include "tss2_policy.h"

#define TSS2_SYNC(r, msg, label, ...)                                                              \
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN)                                                      \
        return TSS2_FAPI_RC_TRY_AGAIN;                                                             \
    if (r != TSS2_RC_SUCCESS) {                                                                    \
        LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ##__VA_ARGS__);                   \
        goto label;                                                                                \
    }

TSS2_RC
ipolicy_copy(const TPMS_POLICY *source, TPMS_POLICY **destination);

void cleanup_policy_element(TPMT_POLICYELEMENT *policy);
void cleanup_policy_elements(TPML_POLICYELEMENTS *policy);

TSS2_RC
ipolicy_compute_policy_digest(const TPML_PCRVALUES *pcrs,
                              TPML_PCR_SELECTION   *pcr_selection,
                              TPMI_ALG_HASH         hash_alg,
                              TPM2B_DIGEST         *pcr_digest);

void ipolicy_helper_init_policy_pcr_selections(TSS2_POLICY_PCR_SELECTION *selection,
                                               const TPMT_POLICYELEMENT  *element);

#endif /* IPOLICY_HELPERS_H */
