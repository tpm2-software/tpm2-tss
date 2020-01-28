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
#include "fapi_int.h"
#include "fapi_crypto.h"
#include "fapi_policy.h"
#include "ifapi_policy_instantiate.h"
#include "ifapi_policy_callbacks.h"
#include "ifapi_helpers.h"
#include "ifapi_json_deserialize.h"
#include "tpm_json_deserialize.h"
#include "ifapi_policy_store.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

/** Compute policy digest for a policy tree.
 *
 * A policy harness or a policy path can be passed. If a harness is passed the
 * policy is computed directly from the harness otherwise the policy has to be
 * retrieved from policy store to determine the policy harness.
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @param[in]     policyPath The policy path for policy store.
 * @param[in]     harness The result of policy deserialization.
 * @param[in]     hash_alg The used hash alg for policy digest computations.
 * @param[out]    digest_idx The index of the current digest. The policy digest can be
 *                computed for several hash algorithms the digets index is a reverence
 *                to the current digest values.
 * @param[out]    hash_size The size of the current policy digest.
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
 */
TSS2_RC
ifapi_calculate_tree(
    FAPI_CONTEXT *context,
    const char *policyPath,
    TPMS_POLICY_HARNESS *harness,
    TPMI_ALG_HASH hash_alg,
    size_t *digest_idx,
    size_t *hash_size)
{
    size_t i;
    TSS2_RC r = TSS2_RC_SUCCESS;
    bool already_computed = false;
    IFAPI_POLICY_EVAL_INST_CTX *eval_ctx = NULL;
    ifapi_policyeval_INST_CB *callbacks;

    if (context->policy.state == POLICY_INIT && !policyPath)
        /* Skip policy reading */
        context->policy.state = POLICY_INSTANTIATE_PREPARE;

    switch (context->policy.state) {
    statecase(context->policy.state, POLICY_INIT);
        fallthrough;

    statecase(context->policy.state, POLICY_READ);
        r = ifapi_policy_store_load_async(&context->pstore, &context->io, policyPath);
        goto_if_error2(r, "Can't open: %s", cleanup, policyPath);
        fallthrough;

    statecase(context->policy.state, POLICY_READ_FINISH);
        r = ifapi_policy_store_load_finish(&context->pstore, &context->io, harness);
        return_try_again(r);
        return_if_error_reset_state(r, "read_finish failed");
        fallthrough;

    statecase(context->policy.state, POLICY_INSTANTIATE_PREPARE);
        eval_ctx = &context->policy.eval_ctx;
        callbacks = &eval_ctx->callbacks;
        callbacks->cbname = ifapi_get_object_name;
        callbacks->cbname_userdata = context;
        callbacks->cbpublic = ifapi_get_key_public;
        callbacks->cbpublic_userdata = context;
        callbacks->cbnvpublic = ifapi_get_nv_public;
        callbacks->cbnvpublic_userdata = context;
        callbacks->cbpcr = ifapi_read_pcr;
        callbacks->cbpcr_userdata = context;

        r = ifapi_policyeval_instantiate_async(eval_ctx, harness, callbacks);
        goto_if_error(r, "Instantiate policy.", cleanup);
        fallthrough;

    statecase(context->policy.state, POLICY_INSTANTIATE);
        r = ifapi_policyeval_instantiate_finish(&context->policy.eval_ctx);
        FAPI_SYNC(r, "Instantiate policy.", cleanup);
        ifapi_free_node_list(context->policy.eval_ctx.policy_elements);
        if (!(*hash_size = ifapi_hash_get_digest_size(hash_alg))) {
            goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                       "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                       hash_alg);
        }

        for (i = 0; i < harness->policyDigests.count; i++) {
            if (harness->policyDigests.digests[i].hashAlg == hash_alg) {
                /* Digest already computed */
                *digest_idx = i;
                already_computed = true;
            }
        }
        if (already_computed)
            break;

        if (i > TPM2_NUM_PCR_BANKS) {
            return_error(TSS2_FAPI_RC_BAD_VALUE, "Table overflow");
        }
        *digest_idx = i;
        harness->policyDigests.count += 1;
        harness->policyDigests.digests[i].hashAlg = hash_alg;

        memset(&harness->policyDigests.digests[*digest_idx].digest, 0,
               sizeof(TPMU_HA));

        r = ifapi_calculate_policy(harness->policy,
                                   &harness->policyDigests, hash_alg,
                                   *hash_size, *digest_idx);
        goto_if_error(r, "Compute policy.", cleanup);

        break;
    statecasedefault(context->policy.state);
    }
cleanup:
    context->policy.state = POLICY_INIT;
    return r;
}

/** Calculate policy and store policy in key template.
 *
 * The policy tree is calculated based on the policy defined by the policy path.
 * The intermediate information of this calculation is stored in the policy field
 * of the context.
 * The resulting policy digest is stored in the key template.
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @param[in]     policyPath the path identifying the policy in policy store.
 * @param[out]    policy_harness The result of policy deserialization.
 * @param[in,out] template The template which will be used for key creation.
 *                The policy digest will be stored in this template.
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
 */
TSS2_RC
ifapi_calculate_policy_for_key(
    FAPI_CONTEXT *context,
    const char *policyPath,
    IFAPI_KEY_TEMPLATE *template,
    TPMS_POLICY_HARNESS **policy_harness)
{
    TSS2_RC r;

    if (policyPath && strcmp(policyPath, "") != 0) {
        r = ifapi_calculate_tree(context, policyPath,
                                 &context->policy.harness,
                                 context->cmd.Key_Create.public_templ.public.publicArea.nameAlg,
                                 &context->policy.digest_idx,
                                 &context->policy.hash_size);
        FAPI_SYNC(r, "Calculate policy tree %s", error_cleanup, policyPath)

        template->public.publicArea.authPolicy.size = context->policy.hash_size;
        memcpy(&template->public.publicArea.authPolicy.buffer[0],
               &context->policy.harness.policyDigests.digests[context->policy.digest_idx].digest,
               context->policy.hash_size);
        /* Store the calculated policy in the key object */
        *policy_harness = calloc(1, sizeof(TPMS_POLICY_HARNESS));
        return_if_null(*policy_harness, "Out of memory.", TSS2_FAPI_RC_MEMORY);
        **policy_harness = context->policy.harness;
        template->public.publicArea.authPolicy.size = context->policy.hash_size;
        memcpy(&template->public.publicArea.authPolicy.buffer[0],
               &context->policy.harness.policyDigests.digests[context->policy.digest_idx].digest,
               context->policy.hash_size);
    } else {
        *policy_harness = NULL;
        return TSS2_RC_SUCCESS;
    }

error_cleanup:
    return r;
}
