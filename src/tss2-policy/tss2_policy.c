/* SPDX-FileCopyrightText: 2022, Intel */
/* SPDX-FileCopyrightText: 2023, Infineon Technologies AG */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h> // for PRIx16, PRIx32
#include <json.h>     // for json_object_put, json_obj...
#include <stdbool.h>  // for true, bool, false
#include <stdlib.h>   // for NULL, free, size_t, calloc
#include <string.h>   // for memcpy, memset, strlen

#include "fapi_int.h"                      // for IFAPI_POLICY_EXEC_CTX
#include "ifapi_io.h"                      // for ifapi_io_poll, IFAPI_IO
#include "ifapi_policy.h"                  // for ifapi_calculate_tree_ex
#include "ifapi_policy_calculate.h"        // for IFAPI_POLICY_EXEC_CTX
#include "ifapi_policy_execute.h"          // for IFAPI_POLICY_EXEC_CTX
#include "ifapi_policy_instantiate.h"      // for IFAPI_POLICY_EVAL_INST_CTX
#include "ifapi_policy_json_deserialize.h" // for ifapi_json_TPMS_POLICY_de...
#include "ifapi_policy_json_serialize.h"   // for ifapi_json_TPMS_POLICY_se...
#include "ifapi_policy_types.h"            // for TPMS_POLICY
#include "tpm_json_deserialize.h"          // for ifapi_parse_json
#include "tss2_common.h"                   // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_crypto.h"                   // for ifapi_hash_get_digest_size
#include "tss2_esys.h"                     // for ESYS_CONTEXT, ESYS_TR
#include "tss2_helpers.h"                  // for ifapi_cleanup_policy
#include "tss2_policy.h"                   // for TSS2_POLICY_CTX, TSS2_POL...
#include "tss2_tpm2_types.h"               // for TPM2B_DIGEST, TPMT_HA

#include "ifapi_macros.h"

#define LOGMODULE "policy"
#include "util/log.h" // for LOG_ERROR, str, LOG_TRACE

#define JSON_OBJECT_SAFE_PUT(o)                                                                    \
    do {                                                                                           \
        json_object_put(o);                                                                        \
        (o) = NULL;                                                                                \
    } while (0)

#define policy_check_not_null(X)                                                                   \
    if ((X) == NULL) {                                                                             \
        LOG_ERROR(str(X) " is NULL: BAD_REFERENCE");                                               \
        return TSS2_POLICY_RC_BAD_REFERENCE;                                                       \
    }

struct TSS2_POLICY_CTX {
    bool                       is_calculated;
    TPM2B_DIGEST               digest;
    TPM2_ALG_ID                hash_alg;
    TSS2_POLICY_CALC_CALLBACKS calc_callbacks;
    TSS2_POLICY_EXEC_CALLBACKS exec_callbacks;
    IFAPI_POLICY_EVAL_INST_CTX eval_ctx;
    TPMS_POLICY                policy;
    TPMS_POLICY               *policy_ptr;
    bool                       policy_caller_allocated;
    size_t                     digest_idx;
    size_t                     hash_size;
    struct {
        struct {
            size_t len;
            char  *string;
        } json;
    } calculated;
};

static inline TSS2_RC
fapi_to_policy_rc(TSS2_RC rc) {
    return (rc_layer(rc) == TSS2_FEATURE_RC_LAYER)
               ? TSS2_POLICY_RC_LAYER | (rc & ~TSS2_RC_LAYER_MASK)
               : rc;
}

static inline TSS2_RC
is_try_again(TSS2_RC rc) {
    TSS2_RC layer = rc_layer(rc);
    /*
     * We only care about TSS2_BASE_RC_TRY_AGAIN
     * if it's from one of the known layers that can
     * return that RC. Otherwise, it could be a user
     * defined LAYER for their callback routine or
     * another portion of their custom stack.
     */
    return (base_rc(rc) == TSS2_BASE_RC_TRY_AGAIN)
           && (layer == TSS2_FEATURE_RC_LAYER || layer == TSS2_ESAPI_RC_LAYER
               || layer == TSS2_SYS_RC_LAYER || layer == TSS2_POLICY_RC_LAYER
               || layer == TSS2_TCTI_RC_LAYER);
}

#define CALL_FAPI(fn) fapi_to_policy_rc(fn)

TSS2_RC
ipolicy_calculate_tree_ex(IFAPI_POLICY_EVAL_INST_CTX *context,
                          TPMS_POLICY                *policy,
                          TPMI_ALG_HASH               hash_alg,
                          size_t                     *digest_idx,
                          size_t                     *hash_size) {
    size_t  i;
    TSS2_RC r = TSS2_RC_SUCCESS;
    bool    already_computed = false;

    switch (context->state) {
    statecase(context->state, IPOLICY_INSTANTIATE_PREPARE);
        r = ifapi_policyeval_instantiate_async(context, policy);
        goto_if_error(r, "Instantiate policy.", cleanup);
        fallthrough;

    statecase(context->state, IPOLICY_INSTANTIATE);
        r = ifapi_policyeval_instantiate_finish(context);
        FAPI_SYNC(r, "Instantiate policy.", cleanup);
        ifapi_free_node_list(context->policy_elements);
        context->policy_elements = NULL;

        if (!(*hash_size = ifapi_hash_get_digest_size(hash_alg))) {
            goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Unsupported hash algorithm (%" PRIu16 ")",
                       cleanup, hash_alg);
        }

        for (i = 0; i < policy->policyDigests.count; i++) {
            if (policy->policyDigests.digests[i].hashAlg == hash_alg) {
                /* Digest already computed */
                *digest_idx = i;
                already_computed = true;
            }
        }
        if (already_computed)
            break;

        if (i >= TPM2_NUM_PCR_BANKS) {
            goto_if_error(TSS2_FAPI_RC_BAD_VALUE, "Table overflow", cleanup);
        }
        *digest_idx = i;
        policy->policyDigests.count += 1;
        policy->policyDigests.digests[i].hashAlg = hash_alg;

        memset(&policy->policyDigests.digests[*digest_idx].digest, 0, sizeof(TPMU_HA));

        r = ifapi_calculate_policy(policy->policy, &policy->policyDigests, hash_alg, *hash_size,
                                   *digest_idx);
        goto_if_error(r, "Compute policy.", cleanup);

        break;
    statecasedefault(context->state);
    }
cleanup:
    ifapi_free_node_list(context->policy_elements);
    context->policy_elements = NULL;
    context->state = IPOLICY_INSTANTIATE_PREPARE;
    return r;
}

static TSS2_RC
check_policy_is_calculated(TPMS_POLICY     *policy,
                           TPMI_ALG_HASH    hash_alg,
                           TSS2_POLICY_CTX *policy_ctx) {
    /*
     * determine if it is already calculated by
     * looking to see if their is a digest for the
     * requested hash alg.
     */
    UINT32 i;
    size_t digest_idx = 0;
    for (i = 0; i < policy->policyDigests.count; i++) {
        if (hash_alg == policy->policyDigests.digests[i].hashAlg) {
            policy_ctx->is_calculated = true;
            digest_idx = i;
            break;
        }
    }

    /* yes, its been calculated for this hash alg */
    if (policy_ctx->is_calculated) {

        /* get the hash algorithm size */
        size_t hash_size = ifapi_hash_get_digest_size(hash_alg);
        if (hash_size == 0) {
            return_error2(TSS2_POLICY_RC_BAD_VALUE, "Unsupported hash algorithm (%#" PRIx16 ")",
                          hash_alg);
        }

        /* copy to our internal TPM2b (sized) buffer over the TPMU_HA which is
         * bounded on the largest hash alg in size (makes copy to user easier
         * later).
         */
        memcpy(&policy_ctx->digest.buffer,
               /* Grab any buffer, it's a union of bytes */
               policy->policyDigests.digests[digest_idx].digest.sha512, hash_size);
        policy_ctx->digest.size = hash_size;

        /* calculation success */
        policy_ctx->is_calculated = true;
    }
    return TSS2_RC_SUCCESS;
}

/**
 * Initialize a policy context with a policy and default hash algorithm.
 *
 * The function initializes a new policy context using the supplied policy and
 * hash algorithm. The policy is associated with the created context and the
 * hash algorithm is used as the default algorithm for subsequent policy
 * calculation and execution operations.
 *
 * @param[in] policy The policy used to initialize the policy context.
 * @param[in] hash_alg The default hash algorithm used for the policy.
 * @param[out] policy_ctx The initialized policy context.
 *
 * @retval TSS2_RC_SUCCESS If the policy context was initialized successfully.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE If policy or policy_ctx is NULL.
 * @retval TSS2_FAPI_RC_MEMORY If memory allocation for the policy context fails.
 * @retval TSS2_FAPI_RC_BAD_VALUE If hash_alg is not supported or the policy
 *         contains invalid data.
 */
TSS2_RC
Tss2_PolicySetPolicy(TPMS_POLICY *policy, TPM2_ALG_ID hash_alg, TSS2_POLICY_CTX **policy_ctx) {

    policy_check_not_null(policy);
    policy_check_not_null(policy_ctx);

    TSS2_RC r;

    *policy_ctx = calloc(1, sizeof(TSS2_POLICY_CTX));
    goto_if_null(*policy_ctx, "Could not allocate policy structure", TSS2_POLICY_RC_MEMORY,
                 cleanup);

    (*policy_ctx)->policy_caller_allocated = true;
    (*policy_ctx)->policy_ptr = policy;
    (*policy_ctx)->hash_alg = hash_alg;

    r = check_policy_is_calculated(policy, hash_alg, *policy_ctx);
    goto_if_error(r, "Check policy is calculated", cleanup);

    return TSS2_RC_SUCCESS;

cleanup:
    Tss2_PolicyFinalize(policy_ctx);
    return r;
}

/**
 * Initialize a policy context from a JSON policy.
 *
 * The function parses the supplied JSON policy string and creates the
 * corresponding policy structure. A new policy context is initialized with
 * the parsed policy and the specified default hash algorithm.
 *
 * The hash algorithm is used as the default algorithm for subsequent policy
 * calculation and execution operations.
 *
 * @param[in] json_policy The JSON string containing the policy definition.
 * @param[in] hash_alg The default hash algorithm used for the policy.
 * @param[out] policy_ctx The initialized policy context.
 *
 * @retval TSS2_RC_SUCCESS If the JSON policy was parsed and the policy context
 *         was initialized successfully.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE If json_policy or policy_ctx is NULL.
 * @retval TSS2_FAPI_RC_BAD_VALUE If the JSON policy is invalid or hash_alg is
 *         not supported.
 * @retval TSS2_FAPI_RC_MEMORY If memory allocation for the policy or policy
 *         context fails.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE If an internal error occurs which is not
 *         covered by another return code.
 */
TSS2_RC
Tss2_PolicyInit(const char *json_policy, TPM2_ALG_ID hash_alg, TSS2_POLICY_CTX **policy_ctx) {

    policy_check_not_null(json_policy);
    policy_check_not_null(policy_ctx);

    TPMS_POLICY  tmp_policy = { 0 };
    json_object *jso;
    TSS2_RC      r;

    *policy_ctx = calloc(1, sizeof(TSS2_POLICY_CTX));
    goto_if_null(*policy_ctx, "Could not allocate policy structure", TSS2_POLICY_RC_MEMORY,
                 cleanup);

    (*policy_ctx)->policy_caller_allocated = false;
    (*policy_ctx)->policy_ptr = &(*policy_ctx)->policy;
    (*policy_ctx)->hash_alg = hash_alg;

    jso = ifapi_parse_json(json_policy);
    goto_if_null(jso, "Policy could not be parsed.", TSS2_POLICY_RC_BAD_VALUE, cleanup);

    r = ifapi_json_TPMS_POLICY_deserialize(jso, &tmp_policy);
    json_object_put(jso);
    goto_if_error(r, "Deserialize policy", cleanup);

    r = check_policy_is_calculated(&tmp_policy, hash_alg, *policy_ctx);
    goto_if_error(r, "Check policy is calculated", cleanup);

    (*policy_ctx)->policy = tmp_policy;
    (*policy_ctx)->hash_alg = hash_alg;

    return TSS2_RC_SUCCESS;

cleanup:
    ifapi_cleanup_policy(&tmp_policy);
    Tss2_PolicyFinalize(policy_ctx);
    return r;
}

TSS2_RC
Tss2_PolicySetCalcCallbacks(TSS2_POLICY_CTX            *policy_ctx,
                            TSS2_POLICY_CALC_CALLBACKS *calc_callbacks) {

    policy_check_not_null(policy_ctx);

    if (calc_callbacks) {
        policy_ctx->calc_callbacks = *calc_callbacks;
    } else {
        memset(&policy_ctx->calc_callbacks, 0, sizeof(policy_ctx->calc_callbacks));
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_PolicySetExecCallbacks(TSS2_POLICY_CTX            *policy_ctx,
                            TSS2_POLICY_EXEC_CALLBACKS *exec_callbacks) {

    policy_check_not_null(policy_ctx);

    if (exec_callbacks) {
        policy_ctx->exec_callbacks = *exec_callbacks;
    } else {
        memset(&policy_ctx->exec_callbacks, 0, sizeof(policy_ctx->exec_callbacks));
    }

    return TSS2_RC_SUCCESS;
}

/** Execute a policy on a given policy session.
 *
 * @param[in] policy_ctx The policy context from Tss2_PolicyInstantiate.
 * @param[in] esys_ctx, the ESAPI context to use for policy execution.
 * @param[in] hash_alg The hash algorithm used for the policy computation.
 * @param[in] The ESYS_TR for the policy session to execute policy commands on.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_POLICY_RC_AUTHORIZATION_UNKNOWN If the callback for branch selection is
 *         not defined. This callback will be needed if or policies have to be
 *         executed.
 * @retval TSS2_POLICY_RC_BAD_VALUE If the computed branch index deliverd by the
 *         callback does not identify a branch or If wrong values are detected during execution.
 * @retval TSS2_POLICY_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_POLICY_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_POLICY_RC_IO_ERROR if an error occurs reading the policy file.
 * @retval TSS2_POLICY_RC_BAD_TEMPLATE In a invalid policy is loaded during execution.
 * @retval TSS2_POLICY_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_POLICY_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_POLICY_RC_NULL_CALLBACK is a callback is NULL and needed for policy
 *         execution or calculation.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 */
TSS2_RC
Tss2_PolicyExecute(TSS2_POLICY_CTX *policy_ctx, ESYS_CONTEXT *esys_ctx, ESYS_TR session) {
    policy_check_not_null(policy_ctx);
    policy_check_not_null(esys_ctx);

    TSS2_RC r = TSS2_POLICY_RC_GENERAL_FAILURE;

    if (!policy_ctx->is_calculated) {
        r = Tss2_PolicyCalculate(policy_ctx);
        return_if_error(r, "Could not calculate policy");
    }

    enum IFAPI_STATE_POLICY    state = POLICY_INIT;
    IFAPI_POLICY_EXEC_CTX      context = { 0 };
    IFAPI_POLICY_EVAL_INST_CTX eval_ctx = { 0 };
    IFAPI_IO                   io = { 0 };

    context.session = session;
    context.callbacks = policy_ctx->exec_callbacks;

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        if (io.stream) {
            r = CALL_FAPI(ifapi_io_poll(&io));
            return_if_error(r, "Something went wrong with IO polling");
        }

        r = CALL_FAPI(ifapi_execute_tree_ex(
            &state, &context, &eval_ctx, NULL, /* don't use the fapi policy store *aka pstore */
            &io, NULL,                         /* cause it skip loading policy path */
            policy_ctx->policy_ptr, esys_ctx, policy_ctx->hash_alg, false));

        /* Repeatedly call the finish function, until FAPI has transitioned
          through all execution stages / states of this invocation. */
    } while (is_try_again(r));

    LOG_TRACE("finished, returning: 0x%" PRIx32, r);

    return r;
}

/** Calculate a policy without executing policy commands.
 *
 *
 * @param[in] policy_ctx The policy context from Tss2_PolicyInstantiate.
 * @param[in] hash_alg The hash algorithm used for the policy computation.
 * @param[out] digest The calculated digest of the policy.
 * @param[out] The JSON string of the instantiated policy.
 *
 * @retval TSS2_RC_SUCCESS After the end of the wait.
 * @retval TSS2_FAPI_RC_IO_ERROR if reading the policy file fails.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_MEMORY: if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE If an internal error occurs, which is
 *         not covered by other return codes.
 * @retval TSS2_FAPI_RC_BAD_VALUE If wrong values are detected during policy calculation.
 * @retval TSS2_POLICY_RC_NULL_CALLBACK is a callback is NULL and needed for policy
 *         calculation.
 */
TSS2_RC
Tss2_PolicyCalculate(TSS2_POLICY_CTX *policy_ctx) {
    policy_check_not_null(policy_ctx);

    TSS2_RC r;

    r = Tss2_PolicyCalculate_Async(policy_ctx);
    goto_if_error(r, "Instantiate policy.", cleanup);

    do {
        r = Tss2_PolicyCalculate_Finish(policy_ctx);
    } while (is_try_again(r));
    return_if_error(r, "Something went wrong when calculating the policy tree");

    LOG_TRACE("finished, returning rc: 0x0");

    return r;

cleanup:
    // TODO
    return r;
}

/** Calculate a policy without executing policy commands.
 *
 *
 * @param[in] policy_ctx The policy context from Tss2_PolicyInstantiate.
 * @param[in] hash_alg The hash algorithm used for the policy computation.
 * @param[out] digest The calculated digest of the policy.
 * @param[out] The JSON string of the instantiated policy.
 *
 * @retval TSS2_RC_SUCCESS After the end of the wait.
 * @retval TSS2_FAPI_RC_IO_ERROR if reading the policy file fails.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_MEMORY: if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE If an internal error occurs, which is
 *         not covered by other return codes.
 * @retval TSS2_FAPI_RC_BAD_VALUE If wrong values are detected during policy calculation.
 * @retval TSS2_POLICY_RC_NULL_CALLBACK is a callback is NULL and needed for policy
 *         calculation.
 */
TSS2_RC
Tss2_PolicyCalculate_Async(TSS2_POLICY_CTX *policy_ctx) {
    policy_check_not_null(policy_ctx);
    policy_ctx->is_calculated = false;

    TPM2_ALG_ID hash_alg = policy_ctx->hash_alg;
    UINT32      i;
    policy_ctx->digest_idx = 0;
    for (i = 0; i < policy_ctx->policy_ptr->policyDigests.count; i++) {
        if (hash_alg == policy_ctx->policy_ptr->policyDigests.digests[i].hashAlg) {
            policy_ctx->is_calculated = true;
            policy_ctx->digest_idx = i;
            break;
        }
    }

    policy_ctx->eval_ctx.callbacks = policy_ctx->calc_callbacks;

    return TSS2_RC_SUCCESS;
}

/** Calculate a policy without executing policy commands.
 *
 *
 * @param[in] policy_ctx The policy context from Tss2_PolicyInstantiate.
 * @param[in] hash_alg The hash algorithm used for the policy computation.
 * @param[out] digest The calculated digest of the policy.
 * @param[out] The JSON string of the instantiated policy.
 *
 * @retval TSS2_RC_SUCCESS After the end of the wait.
 * @retval TSS2_FAPI_RC_IO_ERROR if reading the policy file fails.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_MEMORY: if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE If an internal error occurs, which is
 *         not covered by other return codes.
 * @retval TSS2_FAPI_RC_BAD_VALUE If wrong values are detected during policy calculation.
 * @retval TSS2_POLICY_RC_NULL_CALLBACK is a callback is NULL and needed for policy
 *         calculation.
 */
TSS2_RC
Tss2_PolicyCalculate_Finish(TSS2_POLICY_CTX *policy_ctx) {
    policy_check_not_null(policy_ctx);

    if (policy_ctx->is_calculated) {
        return TSS2_RC_SUCCESS;
    }

    TSS2_RC r;

    size_t digest_idx = 0;
    size_t hash_size = 0;

    r = ipolicy_calculate_tree_ex(&policy_ctx->eval_ctx, policy_ctx->policy_ptr,
                                  policy_ctx->hash_alg, &digest_idx, &hash_size);

    memcpy(&policy_ctx->digest.buffer,
           /* Grab any buffer, it's a union of bytes */
           policy_ctx->policy_ptr->policyDigests.digests[digest_idx].digest.sha512, hash_size);
    policy_ctx->digest.size = hash_size;
    policy_ctx->digest_idx = digest_idx;
    policy_ctx->hash_size = hash_size;

    /* CALCULATION success */
    policy_ctx->is_calculated = true;

    LOG_TRACE("finished, returning rc: 0x0");

    return r;
}

TSS2_RC
Tss2_PolicyGetCalculatedJSON(TSS2_POLICY_CTX *policy_ctx, char *buffer, size_t *size) {

    policy_check_not_null(policy_ctx);
    policy_check_not_null(size);

    if (!policy_ctx->is_calculated) {
        return TSS2_POLICY_RC_POLICY_NOT_CALCULATED;
    }

    /* cache the calculated json */
    if (!policy_ctx->calculated.json.string) {
        /* Generate JSON string of the policy */
        json_object *jso = NULL;
        TSS2_RC      rc = CALL_FAPI(ifapi_json_TPMS_POLICY_serialize(policy_ctx->policy_ptr, &jso));
        return_if_error(rc, "Policy could not be serialized.");

        policy_ctx->calculated.json.string
            = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        JSON_OBJECT_SAFE_PUT(jso);
        return_if_null(policy_ctx->calculated.json.string, "Converting json to string",
                       TSS2_POLICY_RC_MEMORY);

        /* add extra byte so we can NULL terminate it */
        policy_ctx->calculated.json.len = strlen(policy_ctx->calculated.json.string) + 1;
    }

    /* NULL buffer, let the caller know size */
    if (!buffer) {
        *size = policy_ctx->calculated.json.len;
        return TSS2_RC_SUCCESS;
    }

    /* ensure caller has enough size in buffer and set size */
    if (*size < policy_ctx->calculated.json.len) {
        *size = policy_ctx->calculated.json.len;
        return_if_error(TSS2_POLICY_RC_BUFFER_TOO_SMALL, "Specified buffer is too small");
    }

    /* all good, copy to user ALWAYS NULL TERMINATE */
    *size = policy_ctx->calculated.json.len;
    memcpy(buffer, policy_ctx->calculated.json.string, *size);
    buffer[*size - 1] = '\0';

    return TSS2_RC_SUCCESS;
}

/** Retrieve the description field of a policy.
 *
 * The policy description is only a valid pointer for the lifetime of policy_ctx.
 *
 * @param[in] policy_ctx The policy context from Tss2_PolicyInstantiate.
 * @param[in] description The description from the policy file.
 *
 * @retval TSS2_RC_SUCCESS After the end of the wait.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 */
TSS2_RC
Tss2_PolicyGetDescription(TSS2_POLICY_CTX *policy_ctx, char *buffer, size_t *size) {
    policy_check_not_null(policy_ctx);
    policy_check_not_null(size);

    const char *description = policy_ctx->policy_ptr->description;
    /* length including null termination */
    size_t len = strlen(description) + 1;

    /* NULL buffer let calller know size */
    if (!buffer) {
        *size = len;
        return TSS2_RC_SUCCESS;
    }

    /* specified buffer but too small, let caller know size and error */
    if (*size < len) {
        *size = len;
        return_if_error(TSS2_POLICY_RC_BUFFER_TOO_SMALL, "Specified buffer is too small");
    }

    /* all is well, copy it to user (including null termination) and let them know size */
    *size = len;
    strcpy(buffer, description);

    LOG_TRACE("finished, returning: 0x0");
    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_PolicyGetCalculatedDigest(TSS2_POLICY_CTX *policy_ctx, TPM2B_DIGEST *digest) {
    policy_check_not_null(policy_ctx);
    policy_check_not_null(digest);

    if (!policy_ctx->is_calculated) {
        return TSS2_POLICY_RC_POLICY_NOT_CALCULATED;
    }

    *digest = policy_ctx->digest;

    LOG_TRACE("finished, returning: 0x0");
    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_PolicyGetDigestIdx(TSS2_POLICY_CTX *policy_ctx, size_t *digest_idx, size_t *hash_size) {
    policy_check_not_null(policy_ctx);

    if (!policy_ctx->is_calculated) {
        return TSS2_POLICY_RC_POLICY_NOT_CALCULATED;
    }

    *digest_idx = policy_ctx->digest_idx;
    *hash_size = policy_ctx->hash_size;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_PolicySetHashAlg(TSS2_POLICY_CTX *policy_ctx, TPM2_ALG_ID hash_alg) {
    policy_check_not_null(policy_ctx);
    policy_ctx->hash_alg = hash_alg;
    return TSS2_RC_SUCCESS;
}

void
Tss2_PolicyFinalize(TSS2_POLICY_CTX **policy_ctx) {
    if (!policy_ctx) {
        return;
    }

    TSS2_POLICY_CTX *p = *policy_ctx;
    if (!p) {
        return;
    }
    if (!p->policy_caller_allocated) {
        ifapi_cleanup_policy(&p->policy);
    }
    free(p->calculated.json.string);
    free(p);
    *policy_ctx = NULL;
}
