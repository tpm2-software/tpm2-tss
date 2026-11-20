/* SPDX-FileCopyrightText: 2026, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef IPOLICY_HELPERS_H
#define IPOLICY_HELPERS_H

#include "ipolicy_types.h"
#include "tss2_policy.h"

/* Deep-copy a policy, including authorizations and calculated digests.
 * On failure, *destination is NULL. Source and copy can be freed independently.
 * The output slot must not own an existing policy. A PolicyAuthorizeNV runtime
 * policy_buffer without length cannot be copied and returns BAD_VALUE.
 */
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

/* Append a copied TPM authorization; signature verification is the caller's responsibility.
 * All input pointers must be non-NULL; an empty policyRef has size zero.
 * On failure, the policy remains unchanged. All input objects remain caller-owned.
 */
TSS2_RC
ipolicy_add_authorization(TPMS_POLICY          *policy,
                          const TPMT_SIGNATURE *signature,
                          const TPM2B_DIGEST   *policyRef,
                          const TPMT_PUBLIC    *key);

/* Find an authorization by key type/unique ID and policy reference.
 * NULL policy_ref means an empty reference; NULL signature requests a match only.
 * No match returns SUCCESS with found=false and leaves signature unchanged.
 * Matching PEM signatures are converted to TPM format when requested.
 */
TSS2_RC
ipolicy_get_authorization(const TPMS_POLICY *policy,
                          const TPMT_PUBLIC *key,
                          const TPM2B_NONCE *policy_ref,
                          bool              *found,
                          TPMT_SIGNATURE    *signature);

/* Free an owned policy and all nested allocations, then set *policy to NULL.
 * NULL and a pointer to NULL are accepted.
 */
void ipolicy_cleanup(TPMS_POLICY **policy);

#endif /* IPOLICY_HELPERS_H */
