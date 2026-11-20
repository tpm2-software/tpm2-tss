/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "ipolicy_helpers.h"
#include "tss2_crypto.h"
#include "util/aux_util.h"

#define LOGMODULE policy
#include "util/log.h"

/** Free memory allocated during deserialization of a policy element.
 *
 * Depending on the element type the fields of a policy element are freed.
 *
 * @param[in] policy The policy element.
 */
void
cleanup_policy_element(TPMT_POLICYELEMENT *policy) {
    switch (policy->type) {
    case POLICYSECRET:
        SAFE_FREE(policy->element.PolicySecret.objectPath);
        break;
    case POLICYAUTHORIZE:
        SAFE_FREE(policy->element.PolicyAuthorize.keyPath);
        SAFE_FREE(policy->element.PolicyAuthorize.keyPEM);
        break;
    case POLICYAUTHORIZENV:
        SAFE_FREE(policy->element.PolicyAuthorizeNv.nvPath);
        SAFE_FREE(policy->element.PolicyAuthorizeNv.policy_buffer);
        break;
    case POLICYSIGNED:
        SAFE_FREE(policy->element.PolicySigned.keyPath);
        SAFE_FREE(policy->element.PolicySigned.keyPEM);
        SAFE_FREE(policy->element.PolicySigned.publicKeyHint);
        break;
    case POLICYPCR:
        SAFE_FREE(policy->element.PolicyPCR.pcrs);
        break;
    case POLICYNV:
        SAFE_FREE(policy->element.PolicyNV.nvPath);
        break;
    case POLICYDUPLICATIONSELECT:
        SAFE_FREE(policy->element.PolicyDuplicationSelect.newParentPath);
        break;
    case POLICYNAMEHASH:
        for (size_t i = 0; i < 3; i++) {
            SAFE_FREE(policy->element.PolicyNameHash.namePaths[i]);
        }
        break;
    case POLICYACTION:
        SAFE_FREE(policy->element.PolicyAction.action);
        break;
    default:
        /* Other policies do not need additional cleanup */
        break;
    }
}

/** Free memory allocated during deserialization of a a policy element list.
 *
 * All elements of a policy element list are freed.
 *
 * @param[in] policy The policy element list.
 */
void
cleanup_policy_elements(TPML_POLICYELEMENTS *policy) {
    size_t i, j;
    if (policy != NULL) {
        for (i = 0; i < policy->count; i++) {
            if (policy->elements[i].type == POLICYOR) {
                /* Policy with sub policies */
                TPML_POLICYBRANCHES *branches = policy->elements[i].element.PolicyOr.branches;
                if (!branches)
                    continue;
                for (j = 0; j < branches->count; j++) {
                    SAFE_FREE(branches->authorizations[j].name);
                    SAFE_FREE(branches->authorizations[j].description);
                    cleanup_policy_elements(branches->authorizations[j].policy);
                }
                SAFE_FREE(branches);
            } else {
                cleanup_policy_element(&policy->elements[i]);
            }
        }
        SAFE_FREE(policy);
    }
}

/** Compute PCR selection and a PCR digest for a PCR value list.
 *
 * @param[in]  pcrs The list of PCR values.
 * @param[out] pcr_selection The selection computed based on the
 *             list of PCR values.
 * @param[in]  hash_alg The hash algorithm which is used for the policy computation.
 * @param[out] pcr_digest The computed PCR digest corresponding to the passed
 *             PCR value list.
 *
 * @retval TSS2_RC_SUCCESS if the PCR selection and the PCR digest could be computed..
 * @retval TSS2_POLICY_RC_BAD_VALUE: If inappropriate values are detected in the
 *         input data.
 * @retval TSS2_POLICY_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_POLICY_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_POLICY_RC_GENERAL_FAILURE if an internal error occurred.
 */
TSS2_RC
ipolicy_compute_policy_digest(const TPML_PCRVALUES *pcrs,
                              TPML_PCR_SELECTION   *pcr_selection,
                              TPMI_ALG_HASH         hash_alg,
                              TPM2B_DIGEST         *pcr_digest) {
    TSS2_RC                    r = TSS2_RC_SUCCESS;
    size_t                     i, j;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext = NULL;
    size_t                     hash_size;
    UINT32                     pcr;
    UINT32                     max_pcr = 0;

    memset(pcr_selection, 0, sizeof(TPML_PCR_SELECTION));

    /* Compute PCR selection */
    pcr_selection->count = 0;
    for (i = 0; i < pcrs->count; i++) {
        for (j = 0; j < pcr_selection->count; j++) {
            if (pcrs->pcrs[i].hashAlg == pcr_selection->pcrSelections[j].hash) {
                break;
            }
        }
        if (j == pcr_selection->count) {
            /* New hash alg */
            pcr_selection->count += 1;
            if (pcr_selection->count > TPM2_NUM_PCR_BANKS) {
                return_error(TSS2_POLICY_RC_BAD_VALUE, "More hash algs than banks.");
            }
            pcr_selection->pcrSelections[j].hash = pcrs->pcrs[i].hashAlg;
            pcr_selection->pcrSelections[j].sizeofSelect = 3;
        }
        UINT32 pcrIndex = pcrs->pcrs[i].pcr;
        if (pcrIndex >= TPM2_MAX_PCRS) {
            goto_error(r, TSS2_POLICY_RC_BAD_VALUE, "Invalid PCR index %" PRIu32, cleanup,
                       pcrIndex);
        }
        if (pcrIndex + 1 > max_pcr)
            max_pcr = pcrIndex + 1;
        pcr_selection->pcrSelections[j].pcrSelect[pcrIndex / 8] |= ((BYTE)1) << pcrIndex % 8;
        if ((pcrIndex / 8) + 1 > pcr_selection->pcrSelections[j].sizeofSelect)
            pcr_selection->pcrSelections[j].sizeofSelect = (pcrIndex / 8) + 1;
    }
    /* Compute digest for current pcr selection */
    r = tss2_crypto_hash_start(&cryptoContext, hash_alg);
    return_if_error(r, "crypto hash start");

    if (!(pcr_digest->size = tss2_hash_get_digest_size(hash_alg))) {
        goto_error(r, TSS2_POLICY_RC_BAD_VALUE, "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   hash_alg);
    }

    for (i = 0; i < pcr_selection->count; i++) {
        TPMS_PCR_SELECTION selection = pcr_selection->pcrSelections[i];
        TPMI_ALG_HASH      hashAlg = selection.hash;
        if (!(hash_size = tss2_hash_get_digest_size(hashAlg))) {
            goto_error(r, TSS2_POLICY_RC_BAD_VALUE, "Unsupported hash algorithm (%" PRIu16 ")",
                       cleanup, hashAlg);
        }
        for (pcr = 0; pcr < max_pcr; pcr++) {
            if ((selection.pcrSelect[pcr / 8]) & (((BYTE)1) << (pcr % 8))) {
                /* pcr selected */
                for (j = 0; j < pcrs->count; j++) {
                    if (pcrs->pcrs[j].pcr == pcr) {
                        r = tss2_crypto_hash_update(
                            cryptoContext, (const uint8_t *)&pcrs->pcrs[j].digest, hash_size);
                        goto_if_error(r, "crypto hash update", cleanup);
                    }
                }
            }
        }
    }
    r = tss2_crypto_hash_finish(&cryptoContext, (uint8_t *)&pcr_digest->buffer[0], &hash_size);
cleanup:
    if (cryptoContext)
        tss2_crypto_hash_abort(&cryptoContext);
    return r;
}

void
ipolicy_helper_init_policy_pcr_selections(TSS2_POLICY_PCR_SELECTION *s,
                                          const TPMT_POLICYELEMENT  *pol_element) {
    if (pol_element->element.PolicyPCR.currentPCRs.sizeofSelect > 0) {
        s->type = TSS2_POLICY_PCR_SELECTOR_PCR_SELECT;
        s->selections.pcr_select = pol_element->element.PolicyPCR.currentPCRs;
    } else {
        s->type = TSS2_POLICY_PCR_SELECTOR_PCR_SELECTION;
        s->selections.pcr_selection = pol_element->element.PolicyPCR.currentPCRandBanks;
    }
}

/* Allocate a flexible array without overflowing its allocation size. */
static void *
copy_array_alloc(size_t header, size_t count, size_t element) {
    if (count > (SIZE_MAX - header) / element)
        return NULL;
    return calloc(1, header + count * element);
}

static TSS2_RC
copy_string(const char *source, char **destination) {
    *destination = source ? strdup(source) : NULL;
    return source && !*destination ? TSS2_POLICY_RC_MEMORY : TSS2_RC_SUCCESS;
}

static TSS2_RC copy_policy_elements(const TPML_POLICYELEMENTS *source,
                                    TPML_POLICYELEMENTS      **destination);

/* The destination's owning pointers must never alias the source, even on error. */
#define COPY_STRING(member)                                                                        \
    do {                                                                                           \
        TSS2_RC rc = copy_string(source->member, &destination->member);                            \
        if (rc)                                                                                    \
            return rc;                                                                             \
    } while (0)

static TSS2_RC
copy_policy_branches(const TPML_POLICYBRANCHES *source, TPML_POLICYBRANCHES **out) {
    if (!source)
        return TSS2_RC_SUCCESS;
    TPML_POLICYBRANCHES *copy
        = copy_array_alloc(sizeof(*copy), source->count, sizeof(copy->authorizations[0]));
    if (!copy)
        return TSS2_POLICY_RC_MEMORY;
    *out = copy;
    copy->count = source->count;
    for (size_t i = 0; i < source->count; ++i) {
        const TPMS_POLICYBRANCH *branch = &source->authorizations[i];
        TPMS_POLICYBRANCH       *target = &copy->authorizations[i];
        target->policyDigests = branch->policyDigests;
        TSS2_RC r = copy_string(branch->name, &target->name);
        if (r)
            return r;
        r = copy_string(branch->description, &target->description);
        if (r)
            return r;
        r = copy_policy_elements(branch->policy, &target->policy);
        if (r)
            return r;
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
copy_policy_element(const TPMT_POLICYELEMENT *source, TPMT_POLICYELEMENT *destination) {
    *destination = *source;
    switch (source->type) {
    case POLICYOR:
        destination->element.PolicyOr.branches = NULL;
        return copy_policy_branches(source->element.PolicyOr.branches,
                                    &destination->element.PolicyOr.branches);
    case POLICYSECRET:
        destination->element.PolicySecret.objectPath = NULL;
        COPY_STRING(element.PolicySecret.objectPath);
        break;
    case POLICYAUTHORIZE:
        destination->element.PolicyAuthorize.keyPath = NULL;
        destination->element.PolicyAuthorize.keyPEM = NULL;
        COPY_STRING(element.PolicyAuthorize.keyPath);
        COPY_STRING(element.PolicyAuthorize.keyPEM);
        break;
    case POLICYAUTHORIZENV:
        destination->element.PolicyAuthorizeNv.nvPath = NULL;
        destination->element.PolicyAuthorizeNv.policy_buffer = NULL;
        /* This unused runtime field has no length and cannot be copied safely. */
        if (source->element.PolicyAuthorizeNv.policy_buffer)
            return TSS2_POLICY_RC_BAD_VALUE;
        COPY_STRING(element.PolicyAuthorizeNv.nvPath);
        break;
    case POLICYSIGNED:
        destination->element.PolicySigned.keyPath = NULL;
        destination->element.PolicySigned.keyPEM = NULL;
        destination->element.PolicySigned.publicKeyHint = NULL;
        COPY_STRING(element.PolicySigned.keyPath);
        COPY_STRING(element.PolicySigned.keyPEM);
        COPY_STRING(element.PolicySigned.publicKeyHint);
        break;
    case POLICYPCR: {
        const TPML_PCRVALUES *values = source->element.PolicyPCR.pcrs;
        destination->element.PolicyPCR.pcrs = NULL;
        if (values) {
            TPML_PCRVALUES *copy
                = copy_array_alloc(sizeof(*copy), values->count, sizeof(values->pcrs[0]));
            if (!copy)
                return TSS2_POLICY_RC_MEMORY;
            copy->count = values->count;
            memcpy(copy->pcrs, values->pcrs, values->count * sizeof(values->pcrs[0]));
            destination->element.PolicyPCR.pcrs = copy;
        }
        break;
    }
    case POLICYNV:
        destination->element.PolicyNV.nvPath = NULL;
        COPY_STRING(element.PolicyNV.nvPath);
        break;
    case POLICYDUPLICATIONSELECT:
        destination->element.PolicyDuplicationSelect.newParentPath = NULL;
        COPY_STRING(element.PolicyDuplicationSelect.newParentPath);
        break;
    case POLICYACTION:
        destination->element.PolicyAction.action = NULL;
        COPY_STRING(element.PolicyAction.action);
        break;
    case POLICYNAMEHASH:
        memset(destination->element.PolicyNameHash.namePaths, 0,
               sizeof(destination->element.PolicyNameHash.namePaths));
        for (size_t i = 0; i < 3; ++i) {
            COPY_STRING(element.PolicyNameHash.namePaths[i]);
        }
        break;
    default:
        break;
    }
    return TSS2_RC_SUCCESS;
}
#undef COPY_STRING

static TSS2_RC
copy_policy_elements(const TPML_POLICYELEMENTS *source, TPML_POLICYELEMENTS **out) {
    if (!source)
        return TSS2_RC_SUCCESS;
    TPML_POLICYELEMENTS *copy
        = copy_array_alloc(sizeof(*copy), source->count, sizeof(copy->elements[0]));
    if (!copy)
        return TSS2_POLICY_RC_MEMORY;
    *out = copy;
    copy->count = source->count;
    for (size_t i = 0; i < source->count; ++i) {
        TSS2_RC r = copy_policy_element(&source->elements[i], &copy->elements[i]);
        if (r)
            return r;
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
copy_policy_authorizations(const TPML_POLICYAUTHORIZATIONS *source,
                           TPML_POLICYAUTHORIZATIONS      **out) {
    if (!source)
        return TSS2_RC_SUCCESS;
    TPML_POLICYAUTHORIZATIONS *copy
        = copy_array_alloc(sizeof(*copy), source->count, sizeof(copy->authorizations[0]));
    if (!copy)
        return TSS2_POLICY_RC_MEMORY;
    *out = copy;
    copy->count = source->count;
    for (size_t i = 0; i < source->count; ++i) {
        const TPMS_POLICYAUTHORIZATION *entry = &source->authorizations[i];
        TPMS_POLICYAUTHORIZATION       *target = &copy->authorizations[i];
        *target = *entry;
        target->type = NULL;
        target->keyPEM = NULL;
        target->pemSignature.buffer = NULL;
        TSS2_RC r = copy_string(entry->type, &target->type);
        if (r)
            return r;
        if (entry->type && strcmp(entry->type, "pem") == 0) {
            r = copy_string(entry->keyPEM, &target->keyPEM);
            if (r)
                return r;
            if (entry->pemSignature.size) {
                if (!entry->pemSignature.buffer)
                    return TSS2_POLICY_RC_BAD_VALUE;
                target->pemSignature.buffer = malloc(entry->pemSignature.size);
                if (!target->pemSignature.buffer)
                    return TSS2_POLICY_RC_MEMORY;
                memcpy(target->pemSignature.buffer, entry->pemSignature.buffer,
                       entry->pemSignature.size);
            }
        }
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
ipolicy_copy(const TPMS_POLICY *source, TPMS_POLICY **destination) {
    if (!destination)
        return TSS2_POLICY_RC_BAD_REFERENCE;
    *destination = NULL;
    if (!source)
        return TSS2_POLICY_RC_BAD_REFERENCE;
    TPMS_POLICY *copy = calloc(1, sizeof(TPMS_POLICY));
    if (!copy)
        return TSS2_POLICY_RC_MEMORY;
    copy->policyDigests = source->policyDigests;
    TSS2_RC r = copy_string(source->description, &copy->description);
    if (!r)
        r = copy_policy_elements(source->policy, &copy->policy);
    if (!r)
        r = copy_policy_authorizations(source->policyAuthorizations, &copy->policyAuthorizations);
    if (r) {
        ipolicy_cleanup(&copy);
        return r;
    }
    *destination = copy;
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
authorization_policy_rc(TSS2_RC rc) {
    return rc_layer(rc) == TSS2_FEATURE_RC_LAYER ? TSS2_POLICY_RC_LAYER | (rc & ~TSS2_RC_LAYER_MASK)
                                                 : rc;
}

/** Append a TPM authorization. Inputs are copied; the policy owns the new entry.
 * The caller supplies the signature over the hash of the policy digest and policyRef.
 * This function stores the authorization without verifying the signature.
 */
TSS2_RC
ipolicy_add_authorization(TPMS_POLICY          *policy,
                          const TPMT_SIGNATURE *signature,
                          const TPM2B_DIGEST   *policyRef,
                          const TPMT_PUBLIC    *key) {
    if (!policy || !signature || !policyRef || !key)
        return TSS2_POLICY_RC_BAD_REFERENCE;
    if (policyRef->size > sizeof(policyRef->buffer))
        return TSS2_POLICY_RC_BAD_VALUE;

    size_t count = policy->policyAuthorizations ? policy->policyAuthorizations->count : 0;
    if (count == UINT32_MAX)
        return TSS2_POLICY_RC_MEMORY;

#if SIZE_MAX <= UINT32_MAX
    /* On wider platforms, the UINT32 count bounds the allocation size. */
    if (count >= (SIZE_MAX - sizeof(TPML_POLICYAUTHORIZATIONS)) / sizeof(TPMS_POLICYAUTHORIZATION))
        return TSS2_POLICY_RC_MEMORY;
#endif

    char *type = strdup("tpm");
    if (!type)
        return TSS2_POLICY_RC_MEMORY;
    TPML_POLICYAUTHORIZATIONS *entries
        = realloc(policy->policyAuthorizations,
                  sizeof(*entries) + (count + 1) * sizeof(entries->authorizations[0]));
    if (!entries) {
        free(type);
        return TSS2_POLICY_RC_MEMORY;
    }
    entries->authorizations[count] = (TPMS_POLICYAUTHORIZATION){
        .type = type,
        .signature = *signature,
        .policyRef = *policyRef,
        .key = *key,
    };
    entries->count = count + 1;
    policy->policyAuthorizations = entries;
    return TSS2_RC_SUCCESS;
}

/* Preserve the existing authorization matching rule: type and unique public ID.
 * Algorithm parameters and nameAlg are not part of this comparison.
 */
static bool
policy_public_id_equal(const TPMT_PUBLIC *a, const TPMT_PUBLIC *b) {
    if (a->type != b->type)
        return false;
#define SAME_BUFFER(x, y)                                                                          \
    ((x).size <= sizeof((x).buffer) && (y).size == (x).size                                        \
     && memcmp((x).buffer, (y).buffer, (x).size) == 0)
    switch (a->type) {
    case TPM2_ALG_RSA:
        return SAME_BUFFER(a->unique.rsa, b->unique.rsa);
    case TPM2_ALG_ECC:
        return SAME_BUFFER(a->unique.ecc.x, b->unique.ecc.x)
               && SAME_BUFFER(a->unique.ecc.y, b->unique.ecc.y);
    case TPM2_ALG_KEYEDHASH:
        return SAME_BUFFER(a->unique.keyedHash, b->unique.keyedHash);
    case TPM2_ALG_SYMCIPHER:
        return SAME_BUFFER(a->unique.sym, b->unique.sym);
    default:
        return false;
    }
#undef SAME_BUFFER
}

/** Find the first authorization matching key and policy_ref.
 * NULL policy_ref denotes an empty reference. A NULL signature requests only
 * a match check, without converting a PEM signature. No match is success with
 * found=false. Signature is copied only on success with found=true.
 */
TSS2_RC
ipolicy_get_authorization(const TPMS_POLICY *policy,
                          const TPMT_PUBLIC *key,
                          const TPM2B_NONCE *policy_ref,
                          bool              *found,
                          TPMT_SIGNATURE    *signature) {
    if (!found)
        return TSS2_POLICY_RC_BAD_REFERENCE;
    *found = false;
    if (!policy || !key)
        return TSS2_POLICY_RC_BAD_REFERENCE;
    size_t ref_size = policy_ref ? policy_ref->size : 0;
    if (ref_size > sizeof(((TPM2B_NONCE *)0)->buffer))
        return TSS2_POLICY_RC_BAD_VALUE;
    if (!policy->policyAuthorizations)
        return TSS2_RC_SUCCESS;

    const TPML_POLICYAUTHORIZATIONS *entries = policy->policyAuthorizations;
    for (size_t i = 0; i < entries->count; ++i) {
        const TPMS_POLICYAUTHORIZATION *entry = &entries->authorizations[i];
        if (entry->policyRef.size != ref_size
            || (ref_size && memcmp(entry->policyRef.buffer, policy_ref->buffer, ref_size)))
            continue;
        if (!entry->type)
            return TSS2_POLICY_RC_BAD_VALUE;
        bool pem = strcmp(entry->type, "pem") == 0;
        if (!pem && strcmp(entry->type, "tpm") != 0)
            return TSS2_POLICY_RC_BAD_VALUE;
        TPM2B_PUBLIC public = { 0 };
        const TPMT_PUBLIC *candidate = &entry->key;
        TSS2_RC            r;
        if (pem) {
            if (!entry->keyPEM)
                return TSS2_POLICY_RC_BAD_VALUE;
            r = authorization_policy_rc(ifapi_get_tpm2b_public_from_pem(entry->keyPEM, &public));
            return_if_error(r, "Parse authorization key.");
            if (public.publicArea.type == TPM2_ALG_RSA)
            public.publicArea.parameters.rsaDetail.scheme = entry->rsaScheme;
            public.publicArea.nameAlg = entry->hashAlg;
            candidate = &public.publicArea;
        }
        if (!policy_public_id_equal(key, candidate))
            continue;
        if (signature) {
            TPMT_SIGNATURE result;
            if (pem) {
                if (entry->pemSignature.size && !entry->pemSignature.buffer)
                    return TSS2_POLICY_RC_BAD_VALUE;
                r = authorization_policy_rc(
                    tss2_der_sig_to_tpm(candidate, entry->pemSignature.buffer,
                                        entry->pemSignature.size, entry->hashAlg, &result));
                return_if_error(r, "Convert authorization signature.");
            } else {
                result = entry->signature;
            }
            *signature = result;
        }
        *found = true;
        return TSS2_RC_SUCCESS;
    }
    return TSS2_RC_SUCCESS;
}

/** Free memory allocated during deserialization of policy.
 *
 * The policy and its contents are freed and the caller's pointer is set to NULL.
 *
 * @param[in,out] policy_ptr The pointer to the policy to be freed.
 *
 */
void
ipolicy_cleanup(TPMS_POLICY **policy_ptr) {
    if (policy_ptr && *policy_ptr) {
        TPMS_POLICY *policy = *policy_ptr;
        SAFE_FREE(policy->description);
        if (policy->policyAuthorizations) {
            for (size_t i = 0; i < policy->policyAuthorizations->count; i++) {
                if (policy->policyAuthorizations->authorizations[i].type
                    && strcmp(policy->policyAuthorizations->authorizations[i].type, "pem") == 0) {
                    SAFE_FREE(policy->policyAuthorizations->authorizations[i].keyPEM);
                    SAFE_FREE(policy->policyAuthorizations->authorizations[i].pemSignature.buffer);
                }
                SAFE_FREE(policy->policyAuthorizations->authorizations[i].type);
            }
        }
        SAFE_FREE(policy->policyAuthorizations);
        cleanup_policy_elements(policy->policy);
        SAFE_FREE(*policy_ptr);
    }
}
