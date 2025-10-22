/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdbool.h>             // for false, true
#include <stdio.h>               // for size_t, NULL
#include <stdlib.h>              // for calloc
#include <string.h>              // for memcpy, strlen, memset, strcmp

#include "fapi_int.h"            // for IFAPI_NV_Cmds, FAPI_CONTEXT, IFAPI_P...
#include "fapi_util.h"           // for ifapi_authorize_object, ifapi_esys_s...
#include "ifapi_helpers.h"       // for ifapi_check_nv_index, ifapi_get_nv_s...
#include "ifapi_io.h"            // for ifapi_io_poll
#include "ifapi_keystore.h"      // for IFAPI_NV, ifapi_cleanup_ifapi_object
#include "ifapi_macros.h"        // for goto_if_error_reset_state, statecase
#include "ifapi_policy.h"        // for ifapi_calculate_tree
#include "ifapi_policy_types.h"  // for TPMS_POLICY
#include "ifapi_profiles.h"      // for IFAPI_PROFILES, IFAPI_PROFILE
#include "tss2_common.h"         // for TSS2_RC, BYTE, TSS2_RC_SUCCESS, TSS2...
#include "tss2_esys.h"           // for Esys_SetTimeout, Esys_NV_DefineSpace...
#include "tss2_fapi.h"           // for FAPI_CONTEXT, Fapi_CreateNv, Fapi_Cr...
#include "tss2_policy.h"         // for TSS2_OBJECT
#include "tss2_tcti.h"           // for TSS2_TCTI_TIMEOUT_BLOCK
#include "tss2_tpm2_types.h"     // for TPMS_NV_PUBLIC, TPM2B_NV_PUBLIC, TPM...

#define LOGMODULE fapi
#include "util/log.h"            // for LOG_TRACE, SAFE_FREE, goto_if_error

/** One-Call function for Fapi_CreateNv
 *
 * This command creates an NV index in the TPM using a given path and type.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] path The path to the new NV index
 * @param[in] type The intended type of the new NV index. May be NULL
 * @param[in] size The size of the new NV index in bytes. May be 0 if the size
 *            is inferred from the type
 * @param[in] policyPath The path to the policy that is associated with the new
 *            NV index. May be NULL
 * @param[in] authValue The authorization value that is associated with the new
 *            NV index. May be NULL
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or path is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS: if an NV index already exists at
 *         path.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if type is non-NULL but invalid or does not
 *         match the size.
 * @retval TSS2_FAPI_RC_BAD_PATH: if policyPath is non-NULL and does not map to
 *         a FAPI policy or if path dos not refer to a valid NV index path.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 * @retval TSS2_FAPI_RC_TRY_AGAIN if an I/O operation is not finished yet and
 *         this function needs to be called again.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if a key was not found.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_NV_TOO_SMALL if too many NV handles are defined.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_FAILED if the authorization attempt fails.
 * @retval TSS2_FAPI_RC_POLICY_UNKNOWN if policy search for a certain policy digest
 *         was not successful.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 * @retval TSS2_FAPI_RC_NOT_PROVISIONED FAPI was not provisioned.
 */
TSS2_RC
Fapi_CreateNv(
    FAPI_CONTEXT *context,
    char   const *path,
    char   const *type,
    size_t size,
    char   const *policyPath,
    char   const *authValue)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r, r2;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);

    /* Check whether TCTI and ESYS are initialized */
    return_if_null(context->esys, "Command can't be executed in none TPM mode.",
                   TSS2_FAPI_RC_NO_TPM);

    /* If the async state automata of FAPI shall be tested, then we must not set
       the timeouts of ESYS to blocking mode.
       During testing, the mssim tcti will ensure multiple re-invocations.
       Usually however the synchronous invocations of FAPI shall instruct ESYS
       to block until a result is available. */
#ifndef TEST_FAPI_ASYNC
    r = Esys_SetTimeout(context->esys, TSS2_TCTI_TIMEOUT_BLOCK);
    return_if_error_reset_state(r, "Set Timeout to blocking");
#endif /* TEST_FAPI_ASYNC */

    r = Fapi_CreateNv_Async(context, path, type, size,
                            policyPath, authValue);
    return_if_error_reset_state(r, "NV_CreateWithTemplate");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_CreateNv_Finish(context);
    } while (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN);

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return_if_error_reset_state(r, "NV_CreateWithTemplate");

    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for Fapi_CreateNv
 *
 * This command creates an NV index in the TPM using a given path and type.
 *
 * Call Fapi_CreateNv_Finish to finish the execution of this command.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] path The path to the new NV index
 * @param[in] type The intended type of the new NV index. May be NULL
 * @param[in] size The size of the new NV index in bytes. May be 0 if the size
 *            is inferred from the type
 * @param[in] policyPath The path to the policy that is associated with the new
 *            NV index. May be NULL
 * @param[in] authValue The authorization value that is associated with the new
 *            NV index. May be NULL
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or path is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS: if an NV index already exists at
 *         path.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if type is non-NULL but invalid or does not
 *         match the size.
 * @retval TSS2_FAPI_RC_BAD_PATH: if policyPath is non-NULL and does not map to
 *         a FAPI policy or if path dos not refer to a valid NV index path.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
 */
TSS2_RC
Fapi_CreateNv_Async(
    FAPI_CONTEXT *context,
    char   const *path,
    char   const *type,
    size_t size,
    char   const *policyPath,
    char   const *authValue)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("path: %s", path);
    LOG_TRACE("type: %s", type);
    LOG_TRACE("size: %zi", size);
    LOG_TRACE("policyPath: %s", policyPath);
    LOG_TRACE("authValue: %s", authValue);

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);

    /* Helpful alias pointers */
    IFAPI_NV_Cmds * nvCmd = &(context->nv_cmd);
    TPM2B_AUTH *auth = &nvCmd->auth;
    IFAPI_NV * miscNv = &(nvCmd->nv_object.misc.nv);

    /* Reset all context-internal session state information. */
    r = ifapi_session_init(context);
    return_if_error(r, "Initialize NV_CreateNv");

    /* First check whether an existing object would be overwritten */
    r = ifapi_keystore_check_overwrite(&context->keystore, path);
    return_if_error2(r, "Check overwrite %s", path);

    /* Copy parameters to context for use during _Finish. */
    memset(&context->nv_cmd, 0, sizeof(IFAPI_NV_Cmds));
    if (authValue) {
        if (strlen(authValue) > sizeof(TPMU_HA)) {
            return_error(TSS2_FAPI_RC_BAD_VALUE, "AuthValue too long");
        }

        auth->size = strlen(authValue);
        memcpy(&auth->buffer[0], authValue, auth->size);
    } else {
        auth->size = 0;
    }
    strdup_check(nvCmd->nvPath, path, r, error_cleanup);
    nvCmd->numBytes = size;
    nvCmd->nv_object.objectType = IFAPI_NV_OBJ;
    strdup_check(miscNv->policyInstance, policyPath, r, error_cleanup);

    /* Set the flags of the NV index to be created. If no type is given the empty-string
       default type flags are set. */
    r = ifapi_set_nv_flags(type ? type : "", &nvCmd->public_templ,
                           policyPath);
    goto_if_error(r, "Set key flags for NV object", error_cleanup);

    if (nvCmd->public_templ.public.nvIndex) {
        /* NV index was defined by the user, has to be checked whether the selected index
           is appropriate for the used path. */
        r = ifapi_check_nv_index(path, nvCmd->public_templ.public.nvIndex);
        goto_if_error(r, "Check NV path and NV index", error_cleanup);
    }

    /* Initialize the context state for this operation. */
    context->state = NV_CREATE_READ_PROFILE;
    LOG_TRACE("finished");
    return TSS2_RC_SUCCESS;

error_cleanup:
    /* Cleanup duplicated input parameters that were copied before. */
    SAFE_FREE(nvCmd->nvPath);
    SAFE_FREE(miscNv->policyInstance);
    return r;
}

/** Asynchronous finish function for Fapi_CreateNv
 *
 * This function should be called after a previous Fapi_CreateNv_Async.
 *
 * @param[in,out] context The FAPI_CONTEXT
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_TRY_AGAIN: if the asynchronous operation is not yet
 *         complete. Call this function again later.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if a key was not found.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_BAD_PATH if a path is used in inappropriate context
 *         or contains illegal characters.
 * @retval TSS2_FAPI_RC_NV_TOO_SMALL if too many NV handles are defined.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_FAILED if the authorization attempt fails.
 * @retval TSS2_FAPI_RC_POLICY_UNKNOWN if policy search for a certain policy digest
 *         was not successful.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 * @retval TSS2_FAPI_RC_NOT_PROVISIONED FAPI was not provisioned.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS if the object already exists in object store.
 */
TSS2_RC
Fapi_CreateNv_Finish(
    FAPI_CONTEXT *context)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;
    ESYS_TR nvHandle;

    /* Check for NULL parameters */
    check_not_null(context);

    /* Helpful alias pointers */
    IFAPI_NV_Cmds * nvCmd = &(context->nv_cmd);
    TPM2B_AUTH *auth = &nvCmd->auth;
    IFAPI_OBJECT *hierarchy = &nvCmd->auth_object;
    IFAPI_NV * miscNv = &(nvCmd->nv_object.misc.nv);
    TPM2B_NV_PUBLIC *publicInfo = &miscNv->public;
    TPM2B_NV_PUBLIC *existing_nv_public = NULL;
    TPM2B_DIGEST * authPolicy = &(miscNv->public.nvPublic.authPolicy);
    TPMS_POLICY * policy = &(context->policy.policy);
    TPMS_POLICY ** nvCmdPolicy = &nvCmd->nv_object.policy;
    ESYS_TR auth_session;
    bool nv_exists;

    switch (context->state) {
        statecase(context->state, NV_CREATE_READ_PROFILE)
            /* Mix the provided flags provided via the type with with template
               of the current active crypto profile. */
            r = ifapi_merge_profile_into_nv_template(context,
                    &nvCmd->public_templ);
            goto_if_error_reset_state(r, "Merge profile", error_cleanup);

            /* Store information from template in context */
            miscNv->description = NULL;
            publicInfo->nvPublic = nvCmd->public_templ.public;

            /* Check that the hierarchy for the NV index to be created is "Owner".
               FAPI does not allow the creation of "Platform" NV indexes. */
            if (nvCmd->public_templ.hierarchy == TPM2_RH_OWNER) {
                miscNv->hierarchy = ESYS_TR_RH_OWNER;
            } else {
                goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong hierarchy", error_cleanup);
            }

            /* Load the Storage Hierarchy "Owner" meta data for used during
               NV creation authorization. */
            r = ifapi_keystore_load_async(&context->keystore, &context->io, "HS");
            return_if_error_reset_state(r, "Could not open storage hierarchy  HS");
            fallthrough;

        statecase(context->state, NV_CREATE_READ_HIERARCHY)
            r = ifapi_keystore_load_finish(&context->keystore, &context->io,
                                           &nvCmd->auth_object);
            return_try_again(r);
            goto_if_error_reset_state(r, "read_finish failed", error_cleanup);

            /* Initialize the esys object for the hierarchy. */
            r = ifapi_initialize_object(context->esys, &nvCmd->auth_object);
            goto_if_error_reset_state(r, "Initialize NV object", error_cleanup);

            nvCmd->auth_object.public.handle
                = miscNv->hierarchy;

            /* Check if a policy is set for the NV index to be created. */
            if (miscNv->policyInstance &&
                    strcmp(miscNv->policyInstance, "") != 0)
                nvCmd->skip_policy_computation = false;
            else
                nvCmd->skip_policy_computation = true;
            fallthrough;

        statecase(context->state, NV_CREATE_CALCULATE_POLICY)
            if (!nvCmd->skip_policy_computation) {
                /* Calculate the policy as read for the keystore. */
                r = ifapi_calculate_tree(context,
                                         miscNv->policyInstance,
                                         policy,
                                         miscNv->public.nvPublic.nameAlg,
                                         &context->policy.digest_idx,
                                         &context->policy.hash_size);
                return_try_again(r);

                goto_if_error2(r, "Calculate policy tree %s", error_cleanup,
                               context->cmd.Key_Create.policyPath);

                /* Store the calculated policy in the NV object */
                *nvCmdPolicy = calloc(1,
                        sizeof(TPMS_POLICY));
                goto_if_null(*nvCmdPolicy,
                        "Out of memory,", TSS2_FAPI_RC_MEMORY, error_cleanup);
                **(nvCmdPolicy) = *policy;

                authPolicy->size =
                    context->policy.hash_size;
                memcpy(&authPolicy->buffer[0],
                       &policy->policyDigests.digests[context->policy.digest_idx].digest,
                       context->policy.hash_size);
                LOGBLOB_TRACE(
                    &authPolicy->buffer[0],
                    context->policy.hash_size, "Create Key Policy");
            }
            fallthrough;

        statecase(context->state, NV_CREATE_GET_INDEX)
            if (nvCmd->public_templ.public.nvIndex) {
                 /* Check nv index passed by user was already defined*/
                context->state = NV_CREATE_CHECK_EXISTING;
                return TSS2_FAPI_RC_TRY_AGAIN;
            } else {
                r = ifapi_get_nv_start_index(nvCmd->nvPath,
                                             &publicInfo->nvPublic.nvIndex);
                goto_if_error_reset_state(r, "FAPI get handle index.", error_cleanup);

                /* We are searching for a new free NV-index handle. */
                r = ifapi_get_free_handle_async(context, &publicInfo->nvPublic.nvIndex);
                goto_if_error_reset_state(r, "FAPI get handle index.", error_cleanup);
                nvCmd->maxNvIndex = publicInfo->nvPublic.nvIndex + 100;
            }

            fallthrough;

        statecase(context->state, NV_CREATE_FIND_INDEX)
            /* Get nv index if not already defined. */
            r = ifapi_get_free_handle_finish(context, &publicInfo->nvPublic.nvIndex,
                                             nvCmd->maxNvIndex);
            return_try_again(r);
            goto_if_error_reset_state(r, "FAPI get handle index.", error_cleanup);

            fallthrough;
        statecase(context->state, NV_CREATE_INDEX)

            /* Start a authorization session for the NV creation. */
            context->primary_state = PRIMARY_INIT;
            r = ifapi_get_sessions_async(context,
                                         IFAPI_SESSION_GEN_SRK | IFAPI_SESSION1,
                                         TPMA_SESSION_DECRYPT, 0);
            goto_if_error_reset_state(r, "Create sessions", error_cleanup);
            fallthrough;

        statecase(context->state, NV_CREATE_WAIT_FOR_SESSION)
            r = ifapi_get_sessions_finish(context, &context->profiles.default_profile,
                                          context->profiles.default_profile.nameAlg);
            return_try_again(r);
            goto_if_error_reset_state(r, " FAPI create session", error_cleanup);

            fallthrough;

        statecase(context->state, NV_CREATE_AUTHORIZE_HIERARCHY)
            /* Authorize with the storage hierarchy "owner" for NV creation. */
            r = ifapi_authorize_object(context, &nvCmd->auth_object, &auth_session);
            FAPI_SYNC(r, "Authorize hierarchy.", error_cleanup);

            /* Create the NV Index. */
            r = Esys_NV_DefineSpace_Async(context->esys,
                                          hierarchy->public.handle,
                                          auth_session,
                                          ENC_SESSION_IF_POLICY(auth_session),
                                          ESYS_TR_NONE,
                                          auth,
                                          publicInfo);
            goto_if_error_reset_state(r, " Fapi_CreateNv_Async", error_cleanup);
            fallthrough;

        statecase(context->state, NV_CREATE_AUTH_SENT)
            r = Esys_NV_DefineSpace_Finish(context->esys, &nvHandle);
            return_try_again(r);

            goto_if_error_reset_state(r, "FAPI CreateWithTemplate_Finish", error_cleanup);

            nvCmd->nv_object.public.handle = nvHandle;

            fallthrough;

        statecase(context->state, NV_CREATE_SERIALIZE)
            /* Store whether the NV index requires a password. */
            if (nvCmd->auth.size > 0)
                miscNv->with_auth = TPM2_YES;
            else
                miscNv->with_auth = TPM2_NO;

            /* NV objects will always be stored in the system store */
            nvCmd->nv_object.system = TPM2_YES;

            /* Perform esys serialization if necessary */
            r = ifapi_esys_serialize_object(context->esys, &nvCmd->nv_object);
            goto_if_error(r, "Prepare serialization", error_cleanup);

            /* Check whether object already exists in key store.*/
            r = ifapi_keystore_object_does_not_exist(&context->keystore,
                                                     nvCmd->nvPath,
                                                     &nvCmd->nv_object);
            goto_if_error_reset_state(r, "Could not write: %sh", error_cleanup,
                                      nvCmd->nvPath);

            /* Start writing the NV object to the key store */
            r = ifapi_keystore_store_async(&context->keystore, &context->io,
                                           nvCmd->nvPath,
                                           &nvCmd->nv_object);
            goto_if_error_reset_state(r, "Could not open: %sh", error_cleanup,
                                      nvCmd->nvPath);

            fallthrough;

        statecase(context->state, NV_CREATE_WRITE)
            /* Finish writing the NV object to the key store */
            r = ifapi_keystore_store_finish(&context->io);
            return_try_again(r);
            return_if_error_reset_state(r, "write_finish failed");

            break;

        statecase(context->state, NV_CREATE_CHECK_EXISTING)
            r = ifapi_check_existing_nv(context, publicInfo->nvPublic.nvIndex, &nv_exists,
                                        &nvCmd->nv_object.public.handle,
                                        &existing_nv_public);
            return_try_again(r);
            return_if_error_reset_state(r, "checking whether nv index exists failed");

            if (nv_exists) {
                if (publicInfo->nvPublic.dataSize != existing_nv_public->nvPublic.dataSize) {
                    LOG_WARNING("Data size from TPM will be used: %u",
                                existing_nv_public->nvPublic.dataSize);
                }
                /* Check whether type is equal */
                if (!((existing_nv_public->nvPublic.attributes & TPMA_NV_TPM2_NT_MASK) ==
                      (publicInfo->nvPublic.attributes & TPMA_NV_TPM2_NT_MASK))) {
                    goto_error(r, TSS2_FAPI_RC_BAD_VALUE,
                               "The existing NV object and the NV object defined "
                               "have different types.",
                               error_cleanup);
                }
                if (existing_nv_public->nvPublic.authPolicy.size) {
                    if (existing_nv_public->nvPublic.attributes & TPMA_NV_POLICYWRITE &&
                        existing_nv_public->nvPublic.attributes & TPMA_NV_POLICYREAD) {
                        /* Check that the two policies are equal */
                        if (existing_nv_public->nvPublic.authPolicy.size ==
                            publicInfo->nvPublic.authPolicy.size &&
                            memcmp(&existing_nv_public->nvPublic.authPolicy.buffer[0],
                                   &publicInfo->nvPublic.authPolicy.buffer[0],
                                   publicInfo->nvPublic.authPolicy.size) == 0) {
                            context->state = NV_CREATE_SERIALIZE;
                        } else {
                            goto_error(r, TSS2_FAPI_RC_BAD_VALUE,
                                       "The two policies do not match.",
                                       error_cleanup);
                        }
                    } else if ((publicInfo->nvPublic.attributes & TPMA_NV_AUTHWRITE) &&
                               (publicInfo->nvPublic.attributes & TPMA_NV_AUTHREAD)) {
                        publicInfo->nvPublic.authPolicy.size = 0;
                        LOG_WARNING("Policy defined for object will be ignored");
                        context->state = NV_CREATE_SERIALIZE;
                    } else {
                        goto_error(r, TSS2_FAPI_RC_BAD_VALUE,
                                   "Object with policy can't be used in FAPI.",
                                   error_cleanup);
                    }
                } else {
                    context->state = NV_CREATE_SERIALIZE;
                }
                *publicInfo = *existing_nv_public;
            } else {
                context->state  = NV_CREATE_INDEX;
            }
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecasedefault(context->state);
    }

    context->state = FAPI_STATE_INIT;
    LOG_DEBUG("success");
    r = TSS2_RC_SUCCESS;

error_cleanup:
    /* Cleanup any intermediate results and state stored in the context. */
    ifapi_cleanup_ifapi_object(&nvCmd->nv_object);
    ifapi_cleanup_ifapi_object(&nvCmd->auth_object);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    SAFE_FREE(miscNv->policyInstance);
    SAFE_FREE(nvCmd->nvPath);
    ifapi_session_clean(context);
    SAFE_FREE(existing_nv_public);
    LOG_TRACE("finished");
    return r;
}
