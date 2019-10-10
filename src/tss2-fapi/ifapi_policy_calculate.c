/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "tss2_mu.h"
#include "fapi_util.h"
#include "fapi_crypto.h"
#include "fapi_policy.h"
#include "ifapi_helpers.h"
#include "ifapi_json_deserialize.h"
#include "tpm_json_deserialize.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

void
copy_policy_digest(TPML_DIGEST_VALUES *dest, TPML_DIGEST_VALUES *src,
                   size_t digest_idx, size_t hash_size, char *txt)
{
    memcpy(&dest->digests[digest_idx].digest, &src->digests[digest_idx].digest,
           hash_size);
    dest->digests[digest_idx].hashAlg = src->digests[digest_idx].hashAlg;
    LOGBLOB_DEBUG((uint8_t *)&dest->digests[digest_idx].digest, hash_size,
                  "%s : Copy digest size: %zu", txt, hash_size);
    dest->count = src->count;
}

void
log_policy_digest(TPML_DIGEST_VALUES *dest, size_t digest_idx, size_t hash_size,
                  char *txt)
{
    LOGBLOB_DEBUG((uint8_t *)&dest->digests[digest_idx].digest, hash_size,
                  "Digest %s", txt);
}

TSS2_RC
ifapi_compute_policy_pcr(
    TPMS_POLICYPCR *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    TPML_PCR_SELECTION pcr_selection;
    size_t digest_idx;
    TPM2B_DIGEST pcr_digest;
    size_t hash_size;

    LOG_TRACE("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    /* Compute PCR selection and pcr digest */
    r = ifapi_compute_policy_digest(policy->pcrs, &pcr_selection,
                                    current_hash_alg, &pcr_digest);
    return_if_error(r, "Compute policy digest and selection.");

    LOG_TRACE("Compute policy");
    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext,
                       &current_digest->digests[digest_idx].digest, hash_size,
                       r, cleanup);
    HASH_UPDATE(cryptoContext, TPM2_CC, TPM2_CC_PolicyPCR, r, cleanup);
    HASH_UPDATE(cryptoContext, TPML_PCR_SELECTION, &pcr_selection, r, cleanup);
    HASH_UPDATE_BUFFER(cryptoContext, &pcr_digest.buffer[0], hash_size, r,
                       cleanup);

    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) & current_digest->
                                 digests[digest_idx].digest, &hash_size);
    return_if_error(r, "crypto hash finish");

cleanup:
    return r;
}

TSS2_RC
calculate_policy_key_param(
    TPM2_CC command_code,
    TPM2B_NAME *name,
    TPM2B_NONCE *policyRef,
    size_t hash_size,
    TPMI_ALG_HASH current_hash_alg,
    TPMU_HA *digest)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    LOGBLOB_DEBUG((uint8_t *) digest, hash_size, "Digest Start");
    HASH_UPDATE_BUFFER(cryptoContext, digest, hash_size, r, cleanup);
    HASH_UPDATE(cryptoContext, TPM2_CC, command_code, r, cleanup);
    if (name && name->size > 0) {
        LOGBLOB_DEBUG(&name->name[0], name->size, "Key name");
        HASH_UPDATE_BUFFER(cryptoContext, &name->name[0],
                           name->size, r, cleanup);
    }
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) digest, &hash_size);
    LOGBLOB_DEBUG((uint8_t *) digest, hash_size, "Digest Finish");
    return_if_error(r, "crypto hash finish");

    /* Use policyRef for second hash computation */
    if (policyRef) {
        r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
        return_if_error(r, "crypto hash start");

        HASH_UPDATE_BUFFER(cryptoContext, digest, hash_size, r, cleanup);
        HASH_UPDATE_BUFFER(cryptoContext, &policyRef->buffer[0],
                           policyRef->size, r, cleanup);
        r = ifapi_crypto_hash_finish(&cryptoContext,
                                     (uint8_t *) digest, &hash_size);
        return_if_error(r, "crypto hash finish");
    }

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_signed(
    TPMS_POLICYSIGNED *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t digest_idx;
    size_t hash_size;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = calculate_policy_key_param(TPM2_CC_PolicySigned,
                                   &policy->publicKey,
                                   &policy->policyRef, hash_size,
                                   current_hash_alg,
                                   &current_digest->digests[digest_idx].digest);
    goto_if_error(r, "crypto hash start", cleanup);

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_authorize_nv(
    TPMS_POLICYAUTHORIZENV *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t digest_idx;
    size_t hash_size;
    TPM2B_NAME nv_name;

    LOG_DEBUG("call");

    r = ifapi_nv_get_name(&policy->nvPublic, &nv_name);
    return_if_error(r, "Compute NV name");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = calculate_policy_key_param(TPM2_CC_PolicyAuthorizeNV,
                                   &nv_name,
                                   NULL, hash_size, current_hash_alg,
                                   &current_digest->digests[digest_idx].digest);
    goto_if_error(r, "crypto hash start", cleanup);

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_duplicate(
    TPMS_POLICYDUPLICATIONSELECT *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    size_t digest_idx;
    size_t hash_size;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    LOG_TRACE("Compute policy");
    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext,
                       &current_digest->digests[digest_idx].digest, hash_size,
                       r, cleanup);
    HASH_UPDATE(cryptoContext, TPM2_CC, TPM2_CC_PolicyDuplicationSelect, r,
                cleanup);
    LOGBLOB_DEBUG(&policy->newParentName.name[0], policy->newParentName.size,
                  "Policy Duplicate Parent Name");
    HASH_UPDATE_BUFFER(cryptoContext, &policy->newParentName.name[0],
                       policy->newParentName.size, r, cleanup);
    HASH_UPDATE(cryptoContext, BYTE, policy->includeObject, r, cleanup);

    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) & current_digest->
                                 digests[digest_idx].digest, &hash_size);
    return_if_error(r, "crypto hash finish");

    LOGBLOB_DEBUG((uint8_t *) & current_digest->digests[digest_idx].digest,
                  hash_size, "Policy Duplicate digest");

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_authorize(
    TPMS_POLICYAUTHORIZE *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t digest_idx;
    size_t hash_size;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = calculate_policy_key_param(TPM2_CC_PolicyAuthorize,
                                   &policy->keyName,
                                   &policy->policyRef, hash_size,
                                   current_hash_alg,
                                   &current_digest->digests[digest_idx].digest);
    goto_if_error(r, "crypto hash start", cleanup);

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_secret(
    TPMS_POLICYSECRET *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t digest_idx;
    size_t hash_size;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = calculate_policy_key_param(TPM2_CC_PolicySecret,
                                   (TPM2B_NAME *)&policy->objectName,
                                   &policy->policyRef, hash_size,
                                   current_hash_alg,
                                   &current_digest->digests[digest_idx].digest);
    goto_if_error(r, "crypto hash start", cleanup);

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_counter_timer(
    TPMS_POLICYCOUNTERTIMER *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    size_t digest_idx;
    size_t hash_size;
    TPM2B_DIGEST counter_timer_hash;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext, &policy->operandB.buffer[0],
                       policy->operandB.size, r, cleanup);
    HASH_UPDATE(cryptoContext, UINT16, policy->offset, r, cleanup);
    HASH_UPDATE(cryptoContext, UINT16, policy->operation, r, cleanup);

    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) &counter_timer_hash.buffer[0], &hash_size);
    return_if_error(r, "crypto hash finish");

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext,
                       &current_digest->digests[digest_idx].digest, hash_size,
                       r, cleanup);
    HASH_UPDATE(cryptoContext, TPM2_CC, TPM2_CC_PolicyCounterTimer, r, cleanup);
    HASH_UPDATE_BUFFER(cryptoContext, &counter_timer_hash.buffer[0],
                       hash_size, r, cleanup);
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) &current_digest->digests[digest_idx].digest,
                                 &hash_size);
cleanup:
    return r;
}

/** Update plolicy if only the command codes is used
 */
TSS2_RC
ifapi_calculate_simple_policy(
    TPM2_CC command_code1,
    TPM2_CC command_code2,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    size_t digest_idx;
    size_t hash_size;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext,
                       &current_digest->digests[digest_idx].digest, hash_size,
                       r, cleanup);
    if (command_code1) {
        HASH_UPDATE(cryptoContext, TPM2_CC, command_code1, r, cleanup);
    }
    if (command_code2) {
        HASH_UPDATE(cryptoContext, TPM2_CC, command_code2, r, cleanup);
    }
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) &current_digest->digests[digest_idx].digest,
                                 &hash_size);

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_physical_presence(
    TPMS_POLICYPHYSICALPRESENCE *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    (void)policy;

    LOG_DEBUG("call");

    r = ifapi_calculate_simple_policy(TPM2_CC_PolicyPhysicalPresence, 0,
            current_digest, current_hash_alg);
    return_if_error(r, "Calculate policy for command code.");

    return r;
}

TSS2_RC
ifapi_calculate_policy_auth_value(
    TPMS_POLICYAUTHVALUE *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    (void)policy;

    LOG_DEBUG("call");

    r = ifapi_calculate_simple_policy(TPM2_CC_PolicyAuthValue, 0,
            current_digest, current_hash_alg);
    return_if_error(r, "Calculate policy auth value.");

    return r;
}

TSS2_RC
ifapi_calculate_policy_password(
    TPMS_POLICYPASSWORD *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    (void)policy;

    LOG_DEBUG("call");

    r = ifapi_calculate_simple_policy(TPM2_CC_PolicyAuthValue, 0,
            current_digest, current_hash_alg);
    return_if_error(r, "Calculate policy password.");

    return r;
}

TSS2_RC
ifapi_calculate_policy_command_code(
    TPMS_POLICYCOMMANDCODE *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;

    LOG_DEBUG("call");

    r = ifapi_calculate_simple_policy(TPM2_CC_PolicyCommandCode, policy->code,
            current_digest, current_hash_alg);
    return_if_error(r, "Calculate policy for command code.");

    return r;
}

/** Compute policy if only a special digest will bed added.
 */
TSS2_RC
ifapi_calculate_policy_digest_hash(
    TPM2B_DIGEST *digest,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg,
    TPM2_CC command_code)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    size_t digest_idx;
    size_t hash_size;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext,
                       &current_digest->digests[digest_idx].digest, hash_size,
                       r, cleanup);
    HASH_UPDATE(cryptoContext, TPM2_CC, command_code, r, cleanup);
    HASH_UPDATE_BUFFER(cryptoContext, &digest->buffer[0],
                       digest->size, r, cleanup);
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) &current_digest->digests[digest_idx].digest,
                                 &hash_size);
cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_name_hash(
    TPMS_POLICYNAMEHASH *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    size_t hash_size;
    size_t i;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    /* Compute name hash from the list of object names */
    for (i = 0; i <= policy->count; i++) {
        HASH_UPDATE_BUFFER(cryptoContext, &policy->objectNames[i].name[0],
                           policy->objectNames[i].size, r,
                           cleanup);
    }
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) &policy->nameHash.buffer[0],
                                 &hash_size);
    return_if_error(r, "crypto hash finish");

    policy->nameHash.size = hash_size;
    r = ifapi_calculate_policy_digest_hash(&policy->nameHash,
                                           current_digest,
                                           current_hash_alg, TPM2_CC_PolicyNameHash);
    return_if_error(r, "Calculate digest hash for policy");

 cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_cp_hash(
    TPMS_POLICYCPHASH *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;

    LOG_DEBUG("call");

    r = ifapi_calculate_policy_digest_hash(&policy->cpHash,
                                           current_digest, current_hash_alg,
                                           TPM2_CC_PolicyCpHash);
    return_if_error(r, "Calculate digest hash for policy");

    return r;
}

TSS2_RC
ifapi_calculate_policy_locality(
    TPMS_POLICYLOCALITY *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    size_t digest_idx;
    size_t hash_size;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext,
                       &current_digest->digests[digest_idx].digest, hash_size,
                       r, cleanup);
    HASH_UPDATE(cryptoContext, TPM2_CC, TPM2_CC_PolicyLocality, r, cleanup);
    HASH_UPDATE(cryptoContext, BYTE, policy->locality, r, cleanup);
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) & current_digest->
                                 digests[digest_idx].digest, &hash_size);

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_nv_written(
    TPMS_POLICYNVWRITTEN *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    size_t digest_idx;
    size_t hash_size;

    LOG_DEBUG("call");

    if (!(hash_size = ifapi_hash_get_digest_size(current_hash_alg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   current_hash_alg);
    }

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext,
                       &current_digest->digests[digest_idx].digest, hash_size,
                       r, cleanup);
    HASH_UPDATE(cryptoContext, TPM2_CC, TPM2_CC_PolicyNvWritten, r, cleanup);
    HASH_UPDATE(cryptoContext, BYTE, policy->writtenSet, r, cleanup);
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) & current_digest->
                                 digests[digest_idx].digest, &hash_size);

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_nv(
    TPMS_POLICYNV *policy,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH current_hash_alg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;
    TPM2B_NAME nv_name;
    size_t hash_size;
    TPM2B_DIGEST nv_hash;
    size_t digest_idx;

    LOG_DEBUG("call");

    memset(&nv_name, 0, sizeof(TPM2B_NAME));

    /* Compute NV name from public info */

    r = ifapi_nv_get_name(&policy->nvPublic, &nv_name);
    return_if_error(r, "Compute NV name");

    r = get_policy_digest_idx(current_digest, current_hash_alg, &digest_idx);
    return_if_error(r, "Get hash alg for digest.");

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext, &policy->operandB.buffer[0],
                       policy->operandB.size, r, cleanup);
    HASH_UPDATE(cryptoContext, UINT16, policy->offset, r, cleanup);
    HASH_UPDATE(cryptoContext, UINT16, policy->operation, r, cleanup);
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) &nv_hash.buffer[0], &hash_size);
    return_if_error(r, "crypto hash finish");

    nv_hash.size = hash_size;

    r = ifapi_crypto_hash_start(&cryptoContext, current_hash_alg);
    return_if_error(r, "crypto hash start");

    HASH_UPDATE_BUFFER(cryptoContext,
                       &current_digest->digests[digest_idx].digest, hash_size,
                       r, cleanup);
    HASH_UPDATE(cryptoContext, TPM2_CC, TPM2_CC_PolicyNV, r, cleanup);
    HASH_UPDATE_BUFFER(cryptoContext, &nv_hash.buffer[0], nv_hash.size, r, cleanup)
    HASH_UPDATE_BUFFER(cryptoContext, &nv_name.name[0], nv_name.size, r, cleanup);
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) &current_digest->digests[digest_idx].digest,
                                 &hash_size);
    return_if_error(r, "crypto hash finish");

cleanup:
    return r;
}

TSS2_RC
ifapi_calculate_policy_or(
    TPMS_POLICYOR *policyOr,
    TPML_DIGEST_VALUES *current_digest,
    TPMI_ALG_HASH hash_alg,
    size_t hash_size,
    size_t digest_idx)
{
    size_t i;
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext;

    for (i = 0; i < policyOr->branches->count; i++) {
        copy_policy_digest(&policyOr->branches->authorizations[i].policyDigests,
                           current_digest, digest_idx, hash_size,
                           "Copy or digest");

        r = ifapi_calculate_policy(policyOr->branches->authorizations[i].policy,
                                   &policyOr->branches->authorizations[i].
                                   policyDigests, hash_alg, hash_size,
                                   digest_idx);
        log_policy_digest(&policyOr->branches->authorizations[i].policyDigests,
                          digest_idx, hash_size, "Branch digest");

        return_if_error(r, "Compute policy.");
    }
    /* Reset the or policy digest because the digest is included in all sub policies */
    memset(&current_digest->digests[digest_idx], 0, hash_size);
    r = ifapi_crypto_hash_start(&cryptoContext, hash_alg);
    return_if_error(r, "crypto hash start");
    r = ifapi_crypto_hash_update(cryptoContext, (const uint8_t *)
                                 &current_digest->digests[digest_idx].digest,
                                 hash_size);
    return_if_error(r, "crypto hash update");

    uint8_t buffer[sizeof(TPM2_CC)];
    size_t offset = 0;
    r = Tss2_MU_TPM2_CC_Marshal(TPM2_CC_PolicyOR,
                                &buffer[0], sizeof(TPM2_CC), &offset);
    return_if_error(r, "Marshal cc");

    r = ifapi_crypto_hash_update(cryptoContext,
                                 (const uint8_t *)&buffer[0], sizeof(TPM2_CC));
    return_if_error(r, "crypto hash update");

    for (i = 0; i < policyOr->branches->count; i++) {
        r = ifapi_crypto_hash_update(cryptoContext, (const uint8_t *)
                                     &policyOr->branches->authorizations[i]
                                     .policyDigests.digests[digest_idx].digest,
                                     hash_size);
        log_policy_digest(&policyOr->branches->authorizations[i].policyDigests,
                          digest_idx, hash_size, "Or branch");
        current_digest->count =
            policyOr->branches->authorizations[i].policyDigests.count;
        return_if_error(r, "crypto hash update");
    }
    current_digest->digests[digest_idx].hashAlg = hash_alg;
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 (uint8_t *) & current_digest->
                                 digests[digest_idx].digest, &hash_size);
    log_policy_digest(current_digest, digest_idx, hash_size, "Final or digest");
    return_if_error(r, "crypto hash finish");

    return r;
}

TSS2_RC
ifapi_calculate_policy(
    TPML_POLICYELEMENTS *policy,
    TPML_DIGEST_VALUES *policyDigests,
    TPMI_ALG_HASH hash_alg,
    size_t hash_size,
    size_t digest_idx)
{
    size_t i;
    TSS2_RC r = TSS2_RC_SUCCESS;

    for (i = 0; i < policy->count; i++) {

        copy_policy_digest(&policy->elements[i].policyDigests,
                           policyDigests, digest_idx, hash_size,
                           "Copy policy digest (to)");

        switch (policy->elements[i].type) {

        case POLICYPCR:
            r = ifapi_compute_policy_pcr(&policy->elements[i].element.PolicyPCR,
                                         &policy->elements[i].policyDigests,
                                         hash_alg);
            return_if_error(r, "Compute policy pcr");
            break;

        case POLICYSIGNED:
            r = ifapi_calculate_policy_signed(&policy->elements[i].element.
                                              PolicySigned,
                                              &policy->elements[i].
                                              policyDigests, hash_alg);
            return_if_error(r, "Compute policy nv");

            break;

        case POLICYDUPLICATIONSELECT:
            r = ifapi_calculate_policy_duplicate(&policy->elements[i].element.
                                                 PolicyDuplicationSelect,
                                                 &policy->elements[i].
                                                 policyDigests, hash_alg);
            return_if_error(r, "Compute policy duplication select");

            break;

        case POLICYAUTHORIZENV:
            r = ifapi_calculate_policy_authorize_nv(&policy->elements[i].
                                                    element.PolicyAuthorizeNv,
                                                    &policy->elements[i].
                                                    policyDigests, hash_alg);
            return_if_error(r, "Compute policy authorizeg");

            break;

        case POLICYAUTHORIZE:
            r = ifapi_calculate_policy_authorize(&policy->elements[i].element.
                                                 PolicyAuthorize,
                                                 &policy->elements[i].
                                                 policyDigests, hash_alg);
            return_if_error(r, "Compute policy authorizeg");

            break;

        case POLICYSECRET:
            r = ifapi_calculate_policy_secret(&policy->elements[i].element.
                                              PolicySecret,
                                              &policy->elements[i].
                                              policyDigests, hash_alg);
            return_if_error(r, "Compute policy nv");

            break;

        case POLICYOR:
            r = ifapi_calculate_policy_or(&policy->elements[i].element.PolicyOr,
                                          &policy->elements[i].policyDigests,
                                          hash_alg, hash_size, digest_idx);
            return_if_error(r, "Compute policy or");

            break;

        case POLICYNV:
            r = ifapi_calculate_policy_nv(&policy->elements[i].element.PolicyNV,
                                          &policy->elements[i].policyDigests,
                                          hash_alg);
            return_if_error(r, "Compute policy nv");

            break;

        case POLICYNVWRITTEN:
            r = ifapi_calculate_policy_nv_written(&policy->elements[i].element.
                                                  PolicyNvWritten,
                                                  &policy->elements[i].
                                                  policyDigests, hash_alg);
            return_if_error(r, "Compute policy nv written");
            break;

        case POLICYCOUNTERTIMER:
            r = ifapi_calculate_policy_counter_timer(
                    &policy->elements[i].element.PolicyCounterTimer,
                    &policy->elements[i].policyDigests, hash_alg);
            return_if_error(r, "Compute policy counter timer");
            break;

        case POLICYPHYSICALPRESENCE:
            r = ifapi_calculate_policy_physical_presence(
                    &policy->elements[i].element.PolicyPhysicalPresence,
                    &policy->elements[i].policyDigests, hash_alg);
            return_if_error(r, "Compute policy physical presence");
            break;

        case POLICYAUTHVALUE:
            r = ifapi_calculate_policy_auth_value(&policy->elements[i].element.PolicyAuthValue,
                                                  &policy->elements[i].policyDigests, hash_alg);
            return_if_error(r, "Compute policy auth value");
            break;

        case POLICYPASSWORD:
            r = ifapi_calculate_policy_password(&policy->elements[i].element.PolicyPassword,
                                                &policy->elements[i].policyDigests, hash_alg);
            return_if_error(r, "Compute policy password");
            break;

        case POLICYCOMMANDCODE:
            r = ifapi_calculate_policy_command_code(&policy->elements[i].element.PolicyCommandCode,
                                                    &policy->elements[i].policyDigests, hash_alg);
            return_if_error(r, "Compute policy physical presence");
            break;

        case POLICYNAMEHASH:
            r = ifapi_calculate_policy_name_hash(&policy->elements[i].element.PolicyNameHash,
                                                 &policy->elements[i].policyDigests, hash_alg);
            return_if_error(r, "Compute policy  name hash");
            break;

        case POLICYCPHASH:
            r = ifapi_calculate_policy_cp_hash(&policy->elements[i].element.PolicyCpHash,
                                               &policy->elements[i].policyDigests, hash_alg);
            return_if_error(r, "Compute policy cp hash");
            break;

        case POLICYLOCALITY:
            r = ifapi_calculate_policy_locality(&policy->elements[i].element.PolicyLocality,
                                                &policy->elements[i].policyDigests, hash_alg);
            return_if_error(r, "Compute policy locality");
            break;

        case POLICYACTION:
            /* This does not alter the policyDigest */
            break;

        default:
            return_error(TSS2_ESYS_RC_NOT_IMPLEMENTED,
                         "Policy not implemented");
        }

        copy_policy_digest(policyDigests, &policy->elements[i].policyDigests,
                           digest_idx, hash_size, "Copy policy digest (from)");
    }
    return r;
}
