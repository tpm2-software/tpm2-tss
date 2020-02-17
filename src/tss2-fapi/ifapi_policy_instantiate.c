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
//#include "fapi_policy.h"
#include "ifapi_helpers.h"
#include "ifapi_policy_instantiate.h"
#include "ifapi_json_deserialize.h"
#include "tpm_json_deserialize.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

static TSS2_RC
get_policy_elements(TPML_POLICYELEMENTS *policy, NODE_OBJECT_T **policy_element_list);

/** Compute linked list with a list of policy elements which could be instantiated.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
static TSS2_RC
get_policy_elements(TPML_POLICYELEMENTS *policy, NODE_OBJECT_T **policy_element_list)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t i, j;

    for (i = 0; i < policy->count; i++) {
        if (policy->elements[i].type == POLICYOR) {
            /* Policy with sub policies */
            TPML_POLICYBRANCHES *branches = policy->elements[i].element.PolicyOr.branches;
            for (j = 0; j < branches->count; j++) {
                r = get_policy_elements(branches->authorizations[j].policy,
                                        policy_element_list);
                goto_if_error(r, "Get policy elements.", error_cleanup);
            }
        } else {
            r = push_object_to_list(&policy->elements[i], policy_element_list);
            goto_if_error(r, "Get policy elements.", error_cleanup);
        }
    }
    return r;

error_cleanup:
    ifapi_free_node_list(*policy_element_list);
    return r;
}

/** Prepare instantiation a policy template.
 *
 * Parts of policies which are referenced by object paths will be replaced with
 * the appropriate values of the referenced objects.
 *
 * @param[in] context The context storing information for re-entry after try again.
 * @param[in] policy The policy to be instantiated.
 * @param[in] callbacks The needed callback functions with the corresponding user data
 *           which will be passed to the callback.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval FAPI error codes on failure
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_policyeval_instantiate_async(
    IFAPI_POLICY_EVAL_INST_CTX *context, /* For re-entry after try_again for offsets and such */
    TPMS_POLICY *policy, /* in */
    ifapi_policyeval_INST_CB *callbacks)
{
    TSS2_RC r;

    /* Store callbacks and their parameters in context */
    context->callbacks = *callbacks;

    /* Compute list of all policy elements which have to be instantiated */
    if (context->policy_elements) {
        ifapi_free_object_list(context->policy_elements);
        context->policy_elements = NULL;
    }
    r = get_policy_elements(policy->policy, &context->policy_elements);
    return r;
}

static TSS2_RC
set_pem_key_param(
    const char *keyPEM,
    TPMT_PUBLIC *keyPublic,
    TPM2B_NAME *name,
    TPMI_ALG_HASH hash_alg)
{
    TSS2_RC r;
    TPM2B_PUBLIC public;

    if (!keyPEM || strlen(keyPEM) == 0) {
        /* No PEM key used. Parameters are already set in policy. */
        return TSS2_RC_SUCCESS;
    }

    /* Use PEM key to compute public information and name */
    name->size = 0;

    TPM2_ALG_ID rsaOrEcc = ifapi_get_signature_algorithm_from_pem(keyPEM);
    r = ifapi_initialize_sign_public(rsaOrEcc, &public);
    return_if_error(r, "Could not initialize public info of key");

    r = ifapi_get_tpm2b_public_from_pem(keyPEM, &public);
    return_if_error(r, "Invalid PEM key.");

    *keyPublic = public.publicArea;
    keyPublic->nameAlg = hash_alg;
    r = ifapi_get_name(&public.publicArea, name);
    return_if_error(r, "Compute key name.");

    return TSS2_RC_SUCCESS;
}

#define CHECK_TEMPLATE_PATH(path, template) \
     if (!path) { \
         return_error2(TSS2_FAPI_RC_BAD_TEMPLATE, "No path for policy %s", template); \
     }

/** Finalize  instantiation a policy template.
 *
 * All needed asyncroous callbacks will be executed for all policy elements offset
 * The policy.
 *
 * @param[in] context The context storing information for re-entry after try again.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_BAD_TEMPLATE If the templayte is not complete for instantiation.
 * @retval FAPI error codes on failure
 * @retval TSS2_FAPI_RC_TRY_AGAIN if an I/O operation is not finished yet and
 *         this function needs to be called again.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
*          the function.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if a key was not found.
 * @retval TSS2_FAPI_RC_IO_ERROR if an error occurred while accessing the
 *         object store.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 */
TSS2_RC
ifapi_policyeval_instantiate_finish(
    IFAPI_POLICY_EVAL_INST_CTX *context)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    NODE_OBJECT_T *first_in_pol_list = context->policy_elements;
    size_t i_last;

    /* While not all policy elements are instantiated */
    while (first_in_pol_list) {
        TPMT_POLICYELEMENT *pol_element = first_in_pol_list->object;
        switch (pol_element->type) {
        case POLICYSIGNED:
            if (pol_element->element.PolicySigned.keyPublic.type) {
                /* Public info found in template, key path will not be needed. */
                SAFE_FREE(pol_element->element.PolicySigned.keyPath);
                break;
            }

            if (pol_element->element.PolicySigned.keyPEM &&
                strlen(pol_element->element.PolicySigned.keyPEM) > 0) {
                /* Determine name and public info for PEM key. */
                r = set_pem_key_param(pol_element->element.PolicySigned.keyPEM,
                                      &pol_element->element.PolicySigned.keyPublic,
                                      &pol_element->element.PolicySigned.publicKey,
                                      pol_element->element.PolicySigned.keyPEMhashAlg);
                return_if_error(r, "Set parameter of pem key.");

                /* Clear pem key, will be recreated during execution. */
                SAFE_FREE(pol_element->element.PolicySigned.keyPEM);

                break;
            }
            CHECK_TEMPLATE_PATH(pol_element->element.PolicySigned.keyPath, "PolicySigned");

            /* Public info will be added to policy. */
            r = context->callbacks.cbpublic(pol_element->element.PolicySigned.keyPath,
                                            &pol_element->element.PolicySigned.keyPublic,
                                            context->callbacks.cbpublic_userdata);
            return_try_again(r);
            return_if_error(r, "read_finish failed");
            /* Clear keypath, only public data will be needed */
            SAFE_FREE(pol_element->element.PolicySigned.keyPath);

            break;

        case POLICYNAMEHASH:
            /* Set index of last name to be computed. */
            i_last = pol_element->element.PolicyNameHash.count - 1;
            while (!pol_element->element.PolicyNameHash.objectNames[i_last].size) {
                /* Not all object names have been computed or were initialized */
                size_t i = pol_element->element.PolicyNameHash.i;
                r = context->callbacks.cbname(pol_element->element.PolicyNameHash.namePaths[i],
                                              &pol_element->element.PolicyNameHash.objectNames[i],
                                              context->callbacks.cbname_userdata);
                return_try_again(r);
                return_if_error(r, "get object name.");
                pol_element->element.PolicyNameHash.i++;
                SAFE_FREE(pol_element->element.PolicyNameHash.namePaths[i]);
            }
            break;

        case POLICYSECRET:
            if (pol_element->element.PolicySecret.objectName.size) {
                /* Name found in template, object path will not be needed. */
                SAFE_FREE(pol_element->element.PolicySecret.objectPath);
                break;
            }
            CHECK_TEMPLATE_PATH(pol_element->element.PolicySecret.objectPath, "PolicySecret");
            /* Object name will be added to policy. */
            r = context->callbacks.cbname(pol_element->element.PolicySecret.objectPath,
                                          &pol_element->element.PolicySecret.objectName,
                                          context->callbacks.cbname_userdata);
            return_try_again(r);
            return_if_error(r, "read_finish failed");
            SAFE_FREE(pol_element->element.PolicySecret.objectPath);
            break;

        case POLICYPCR:
            if (pol_element->element.PolicyPCR.pcrs &&
                pol_element->element.PolicyPCR.pcrs->count) {
                /* PCR values already defined */
                break;
            }
            /* Current values of PCRs will be used for policy */
            r = context->callbacks.cbpcr(&pol_element->element.PolicyPCR.currentPCRs,
                                         &pol_element->element.PolicyPCR.currentPCRandBanks,
                                         &pol_element->element.PolicyPCR.pcrs,
                                         context->callbacks.cbpcr_userdata);
            return_try_again(r);
            return_if_error(r, "read_finish failed");

            pol_element->element.PolicyPCR.currentPCRs.sizeofSelect = 0;
            pol_element->element.PolicyPCR.currentPCRandBanks.count = 0;
            break;

        case POLICYNV:
            if (pol_element->element.PolicyNV.nvPublic.nvPublic.nvIndex) {
                /* nvIndex is already set in policy. Path will not be needed */
                pol_element->element.PolicyNV.nvIndex
                    = pol_element->element.PolicyNV.nvPublic.nvPublic.nvIndex;
                SAFE_FREE(pol_element->element.PolicyNV.nvPath);
                break;
            }

            CHECK_TEMPLATE_PATH(pol_element->element.PolicyNV.nvPath, "PolicyNv");
            /* Object name will be added to policy. */
            r = context->callbacks.cbnvpublic(pol_element->element.PolicyNV.nvPath,
                                              &pol_element->element.PolicyNV.nvPublic,
                                              context->callbacks.cbnvpublic_userdata);
            return_try_again(r);
            return_if_error(r, "read_finish failed");

            pol_element->element.PolicyNV.nvIndex
                = pol_element->element.PolicyNV.nvPublic.nvPublic.nvIndex;

            /* Clear NV path, only public data will be needed */
            SAFE_FREE(pol_element->element.PolicyNV.nvPath);
            break;

        case POLICYDUPLICATIONSELECT:
            if (pol_element->element.PolicyDuplicationSelect.newParentPublic.publicArea.type) {
                /* public data is already set in policy. Path will not be needed. */
                SAFE_FREE(pol_element->element.PolicyDuplicationSelect.newParentPath);
                break;
            }

            CHECK_TEMPLATE_PATH(pol_element->element.PolicyDuplicationSelect.newParentPath,
                                "PolicyDuplicationselect");

            /* Public info will be added to policy. */
            r = context->callbacks.cbpublic(
                     pol_element->element.PolicyDuplicationSelect.newParentPath,
                     &pol_element->element.PolicyDuplicationSelect.newParentPublic.publicArea,
                     context->callbacks.cbpublic_userdata);
            return_try_again(r);
            return_if_error(r, "read_finish failed");

            r = ifapi_get_name(
                     &pol_element->element.PolicyDuplicationSelect.newParentPublic.publicArea,
                     &pol_element->element.PolicyDuplicationSelect.newParentName);
            return_if_error(r, "Compute key name");

            /* Clear keypath, only public data will be needed */
            SAFE_FREE(pol_element->element.PolicyDuplicationSelect.newParentPath);
            break;

        case POLICYAUTHORIZENV:
            if (pol_element->element.PolicyAuthorizeNv.nvPublic.nvPublic.nvIndex) {
                /* nvIndex is already set in policy. Path will not be needed */
                SAFE_FREE(pol_element->element.PolicyAuthorizeNv.nvPath);
                break;
            }

            CHECK_TEMPLATE_PATH(pol_element->element.PolicyAuthorizeNv.nvPath,
                                "PolicyAuthorizeNv");
            /* Object name will be added to policy. */
            r = context->callbacks.cbnvpublic(pol_element->element.PolicyAuthorizeNv.nvPath,
                                              &pol_element->element.PolicyAuthorizeNv.nvPublic,
                                              context->callbacks.cbnvpublic_userdata);
            return_try_again(r);
            return_if_error(r, "read_finish failed");
            /* Clear NV path, only public data will be needed */
            SAFE_FREE(pol_element->element.PolicyAuthorizeNv.nvPath);
            break;

        case POLICYAUTHORIZE:
            if (pol_element->element.PolicyAuthorize.keyPublic.type) {
                /* Public info found in template, key path will not be needed. */
                SAFE_FREE(pol_element->element.PolicyAuthorize.keyPath);
                r = ifapi_get_name(&pol_element->element.PolicyAuthorize.keyPublic,
                                   &pol_element->element.PolicyAuthorize.keyName);
                return_if_error(r, "Compute key name");

                break;
            }

            if (pol_element->element.PolicyAuthorize.keyPEM &&
                strlen(pol_element->element.PolicyAuthorize.keyPEM) > 0) {
                /* Determine name and public info for PEM key. */
                r = set_pem_key_param(pol_element->element.PolicyAuthorize.keyPEM,
                                      &pol_element->element.PolicyAuthorize.keyPublic,
                                      &pol_element->element.PolicyAuthorize.keyName,
                                      pol_element->element.PolicyAuthorize.keyPEMhashAlg);
                return_if_error(r, "Set parameter of pem key.");

                pol_element->element.PolicyAuthorize.keyPEM = NULL;

                break;
            }

            CHECK_TEMPLATE_PATH(pol_element->element.PolicyAuthorize.keyPath, "PolicyAuthorize");

            /* Object public data will be added to policy. */
            r = context->callbacks.cbpublic(pol_element->element.PolicyAuthorize.keyPath,
                                            &pol_element->element.PolicyAuthorize.keyPublic,
                                            context->callbacks.cbpublic_userdata);
            return_try_again(r);
            return_if_error(r, "read_finish failed");

            /* Compute key name from public info */
            r = ifapi_get_name(&pol_element->element.PolicyAuthorize.keyPublic,
                               &pol_element->element.PolicyAuthorize.keyName);
            return_if_error(r, "Compute key name");

            /* Clear key path, only public data will be needed */
            SAFE_FREE(pol_element->element.PolicyAuthorize.keyPath);
            break;
        }
        /* Cleanup head of list and use next policy element */
        context->policy_elements = first_in_pol_list->next;
        SAFE_FREE(first_in_pol_list);
    }
    return r;
}
