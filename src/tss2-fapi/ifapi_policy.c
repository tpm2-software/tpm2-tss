/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h> // for PRIu16
#include <stdbool.h>  // for bool, false, true
#include <string.h>   // for memset

#include "fapi_int.h"      // for IFAPI_POLICY_CTX, POLICY_INIT
#include "ifapi_helpers.h" // for tss2_free_node_list
#include "ifapi_io.h"      // for IFAPI_IO
#include "ifapi_macros.h"  // for statecase, fallthrough, return...
#include "ifapi_policy.h"
#include "ifapi_policy_store.h" // for ifapi_policy_store_load_async
#include "tss2_common.h"        // for TSS2_RC, TSS2_FAPI_RC_BAD_VALUE
#include "tss2_crypto.h"        // for tss2_hash_get_digest_size
#include "tss2_esys.h"          // for ESYS_CONTEXT
#include "tss2_helpers.h"       // for free_node_list
#include "tss2_helpers.h"       // for tss2_free_node_list
#include "tss2_policy.h"        // for the opaque Policy API
#include "tss2_tpm2_types.h"    // for TPMT_HA, TPML_DIGEST_VALUES

#define LOGMODULE fapi
#include "util/log.h" // for goto_if_error, goto_error

/** Compute policy digest for a policy tree.
 *
 * A policy or a policy path can be passed. If a policy is passed the
 * policy is computed directly from the policy otherwise the policy has to be
 * retrieved from policy store to determine the policy.
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @param[in]     policyPath The policy path for policy store.
 * @param[in,out] policy The result of policy deserialization.
 * @param[in]     hash_alg The used hash alg for policy digest computations.
 * @param[out]    digest The calculated policy digest.
 *
 * @retval TSS2_FAPI_RC_MEMORY: if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE If an internal error occurs, which is
 *         not covered by other return codes.
 * @retval TSS2_FAPI_RC_BAD_VALUE If wrong values are detected during policy calculation.
 * @retval TSS2_FAPI_RC_IO_ERROR If an error occurs during access to the policy
 *         store.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND If an object needed for policy calculation was
 *         not found.
 * @retval TSS2_FAPI_RC_POLICY_UNKNOWN If policy search for a certain policy digest was
 *         not successful.
 * @retval TSS2_FAPI_RC_TRY_AGAIN if an I/O operation is not finished yet and
 *         this function needs to be called again.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if a key was not found.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 * @retval TSS2_FAPI_RC_NOT_PROVISIONED FAPI was not provisioned.
 * @retval TSS2_FAPI_RC_BAD_PATH if the path is used in inappropriate context
 *         or contains illegal characters.
 */
TSS2_RC
ifapi_calculate_tree_ex(IFAPI_POLICY_CTX   *context,
                        IFAPI_POLICY_STORE *pstore,
                        IFAPI_IO           *io,
                        const char         *policyPath,
                        char              **policy,
                        TPMI_ALG_HASH       hash_alg,
                        TPM2B_DIGEST       *digest) {
    TSS2_RC r = TSS2_RC_SUCCESS;
    char   *updated_policy = NULL;

    if (context->state == POLICY_INIT && !policyPath)
        /* Skip policy reading */
        context->state = POLICY_INSTANTIATE_PREPARE;

    switch (context->state) {
    statecase(context->state, POLICY_INIT);
        fallthrough;

    statecase(context->state, POLICY_READ);
        r = ifapi_policy_store_load_async(pstore, io, policyPath);
        if (r) {
            LOG_ERROR("Can't open: %s", policyPath);
            goto cleanup;
        }
        fallthrough;

    statecase(context->state, POLICY_READ_FINISH);
        r = ifapi_policy_store_load_finish(pstore, io, policy);
        ifapi_return_try_again(r);
        if (r) {
            LOG_ERROR("read_finish failed");
            goto cleanup;
        }
        fallthrough;

    statecase(context->state, POLICY_INSTANTIATE_PREPARE);
        r = policy_to_fapi_rc(Tss2_PolicyInit(*policy, hash_alg, &context->tss2_policy_ctx));
        goto_if_error(r, "Instantiate policy.", cleanup);

        r = policy_to_fapi_rc(
            Tss2_PolicySetCalcCallbacks(context->tss2_policy_ctx, &context->calc_callbacks));
        goto_if_error(r, "Set policy calc callbacks.", cleanup);

        r = policy_to_fapi_rc(Tss2_PolicyCalculate_Async(context->tss2_policy_ctx));
        goto_if_error(r, "Instantiate policy.", cleanup);
        fallthrough;

    statecase(context->state, POLICY_INSTANTIATE);
        r = policy_to_fapi_rc(Tss2_PolicyCalculate_Finish(context->tss2_policy_ctx));
        FAPI_SYNC(r, "Instantiate policy.", cleanup);

        r = policy_to_fapi_rc(Tss2_PolicyGetCalculatedDigest(context->tss2_policy_ctx, digest));
        goto_if_error(r, "Copy policy.", cleanup);

        r = policy_to_fapi_rc(Tss2_PolicyGetJSON(context->tss2_policy_ctx, &updated_policy));
        goto_if_error(r, "Serialize calculated policy.", cleanup);
        SAFE_FREE(*policy);
        *policy = updated_policy;
        updated_policy = NULL;

        break;
    ifapi_statecasedefault(context->state);
    }
cleanup:
    SAFE_FREE(updated_policy);
    Tss2_PolicyFinalize(&context->tss2_policy_ctx);
    context->state = POLICY_INIT;
    return r;
}

/** Execute a policy tree
 *
 * @param state: The policy state.
 * @param policy_ctx: Caller-owned context slot, initially NULL; retained on TRY_AGAIN.
 * @param callbacks: Execution callbacks and application data.
 *     Callback data and policy must remain valid until execution ends.
 * @param pstore: The policy store, may be NULL and then policy path
 *      is treated as a regular path.
 * @param io: The FAPI IO Context used for async IO.
 * @param policyPath: Relative policy path if pstore is not NULL else an absolute
 *   or relative path to a policy file.
 * @param policy: Policy structure.
 * @param esys_ctx: The ESAPI context used to execute policy commands on.
 * @param session: Caller-owned policy session; must remain the same on retries.
 * @param hash_alg: The hash alg for policy computations.
 * @param do_flush: True to flush the policy session on error, false to not flush.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN If the callback for branch selection is
 *         not defined. This callback will be needed if or policies have to be
 *         executed.
 * @retval TSS2_FAPI_RC_BAD_VALUE If the computed branch index deliverd by the
 *         callback does not identify a branch or If wrong values are detected during execution.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_IO_ERROR if an error occurs reading the policy file.
 * @retval TSS2_FAPI_RC_BAD_TEMPLATE In a invalid policy is loaded during execution.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 */
TSS2_RC
ifapi_execute_tree_ex(enum IFAPI_STATE_POLICY    *state,
                      TSS2_POLICY_CTX           **policy_ctx,
                      TSS2_POLICY_EXEC_CALLBACKS *callbacks,
                      IFAPI_POLICY_STORE         *pstore,
                      IFAPI_IO                   *io,
                      const char                 *policyPath,
                      char                      **policy,
                      ESYS_CONTEXT               *esys_ctx,
                      ESYS_TR                     session,
                      TPMI_ALG_HASH               hash_alg,
                      bool                        do_flush) {
    TSS2_RC r = TSS2_RC_SUCCESS;

    if (!state || !policy_ctx || !policy || !esys_ctx)
        return TSS2_FAPI_RC_BAD_REFERENCE;
    if (*state == POLICY_INIT && *policy_ctx)
        return TSS2_FAPI_RC_BAD_SEQUENCE;

    if (*state == POLICY_INIT && !policyPath) {
        /* Skip policy reading */
        *state = POLICY_EXECUTE_PREPARE;
    }

    switch (*state) {
    statecase(*state, POLICY_INIT);
        fallthrough;

    statecase(*state, POLICY_READ);
        r = ifapi_policy_store_load_async(pstore, io, policyPath);
        if (r) {
            LOG_ERROR("Can't open: %s", policyPath);
            goto cleanup;
        }
        fallthrough;

    statecase(*state, POLICY_READ_FINISH);
        r = ifapi_policy_store_load_finish(pstore, io, policy);
        ifapi_return_try_again(r);
        if (r) {
            LOG_ERROR("read_finish failed");
            goto cleanup;
        }
        fallthrough;

    statecase(*state, POLICY_EXECUTE_PREPARE);
        if (!*policy_ctx) {
            r = policy_to_fapi_rc(Tss2_PolicyInit(*policy, hash_alg, policy_ctx));
            goto_if_error(r, "Set execution policy.", cleanup);
            r = policy_to_fapi_rc(Tss2_PolicySetExecCallbacks(*policy_ctx, callbacks));
            goto_if_error(r, "Set execution callbacks.", cleanup);
        }
        r = policy_to_fapi_rc(Tss2_PolicyExecute_Async(*policy_ctx));
        ifapi_return_try_again(r);
        goto_if_error(r, "execute policy prepare.", cleanup);
        fallthrough;
    statecase(*state, POLICY_EXECUTE);
        r = policy_to_fapi_rc(Tss2_PolicyExecute_Finish(*policy_ctx, esys_ctx, session));
        ifapi_return_try_again(r);
        goto_if_error(r, "execute policy.", cleanup);

        break;
    ifapi_statecasedefault(*state);
    }

cleanup:
    /* Policy execution borrows the session; FAPI retains cleanup ownership. */
    if (r && *state == POLICY_EXECUTE && do_flush && session && session != ESYS_TR_NONE)
        Esys_FlushContext(esys_ctx, session);
    Tss2_PolicyFinalize(policy_ctx);
    *state = POLICY_INIT;
    return r;
}

/* Replace the stored JSON only after the authorization and serialization succeed. */
TSS2_RC
ifapi_policy_add_authorization(char                **policy,
                               const TPMT_SIGNATURE *signature,
                               const TPM2B_DIGEST   *policy_ref,
                               const TPMT_PUBLIC    *key) {
    if (!policy || !*policy)
        return TSS2_FAPI_RC_BAD_REFERENCE;
    TSS2_POLICY_CTX *ctx = NULL;
    char            *updated = NULL;
    TSS2_RC          r = policy_to_fapi_rc(Tss2_PolicyInit(*policy, TPM2_ALG_SHA256, &ctx));
    if (!r)
        r = policy_to_fapi_rc(Tss2_PolicyContextAddAuthorization(ctx, signature, policy_ref, key));
    if (!r)
        r = policy_to_fapi_rc(Tss2_PolicyGetJSON(ctx, &updated));
    if (!r) {
        SAFE_FREE(*policy);
        *policy = updated;
        updated = NULL;
    }
    SAFE_FREE(updated);
    Tss2_PolicyFinalize(&ctx);
    return r;
}

TSS2_RC
ifapi_policy_get_authorization(const char        *policy,
                               const TPMT_PUBLIC *key,
                               const TPM2B_NONCE *policy_ref,
                               bool              *found,
                               TPMT_SIGNATURE    *signature) {
    if (!found)
        return TSS2_FAPI_RC_BAD_REFERENCE;
    *found = false;
    TSS2_POLICY_CTX *ctx = NULL;
    TSS2_RC          r = policy_to_fapi_rc(Tss2_PolicyInit(policy, TPM2_ALG_SHA256, &ctx));
    if (!r)
        r = policy_to_fapi_rc(
            Tss2_PolicyContextGetAuthorization(ctx, key, policy_ref, found, signature));
    Tss2_PolicyFinalize(&ctx);
    return r;
}

/** Instantiate all policies defined in the FAPI profile.
 *
 * The five policies which can be defined in the FAPI profile will be
 * instantiated.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
TSS2_RC
ifapi_instantiate_profile_policies(FAPI_CONTEXT *context) {
    TSS2_RC         r = TSS2_RC_SUCCESS;
    IFAPI_POLICIES *ctx = &context->cmd.Provision.policies;
    size_t          i;
    switch (ctx->state) {
    statecase(ctx->state, POLICIES_INSTANTIATION_INIT);
        ctx->policies[0] = &context->profiles.default_profile.ek_policy;
        ctx->policies[1] = &context->profiles.default_profile.srk_policy;
        ctx->policies[2] = &context->profiles.default_profile.eh_policy;
        ctx->policies[3] = &context->profiles.default_profile.sh_policy;
        ctx->policies[4] = &context->profiles.default_profile.lockout_policy;
        ctx->pol_idx = 0;
        fallthrough;

    statecase(ctx->state, POLICIES_INSTANTIATION_WAIT);
        do {
            for (i = ctx->pol_idx; i < 5 && !*ctx->policies[i]; i++)
                ;
            if (i == 5) {
                return TSS2_RC_SUCCESS;
            }
            TPM2B_DIGEST digest;
            r = ifapi_calculate_tree_ex(&context->policy, NULL, NULL, NULL, ctx->policies[i],
                                        context->profiles.default_profile.nameAlg, &digest);
            ifapi_return_try_again(r);
            return_if_error(r, "Instantiate policy");

            /* default_profile is a shallow view of the selected profile. Keep
             * its owning entry in sync when calculated JSON replaces a string. */
            for (size_t j = 0; j < context->profiles.num_profiles; j++) {
                IFAPI_PROFILE_ENTRY *entry = &context->profiles.profiles[j];
                if (strcmp(entry->name, context->profiles.default_name) == 0) {
                    IFAPI_PROFILE *profile = &context->profiles.default_profile;
                    entry->profile.ek_policy = profile->ek_policy;
                    entry->profile.srk_policy = profile->srk_policy;
                    entry->profile.eh_policy = profile->eh_policy;
                    entry->profile.sh_policy = profile->sh_policy;
                    entry->profile.lockout_policy = profile->lockout_policy;
                    break;
                }
            }
            ctx->pol_idx = i + 1;
        } while (ctx->pol_idx < 5);

        return TSS2_RC_SUCCESS;

    ifapi_statecasedefault(ctx->state);
    }
    return TSS2_RC_SUCCESS;
}
