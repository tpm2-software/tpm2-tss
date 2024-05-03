/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <json.h>                           // for json_object_put, json_tok...
#include <stdint.h>                         // for uint16_t
#include <stdlib.h>                         // for NULL, size_t
#include <string.h>                         // for strncmp, memset, memcpy

#include "fapi_crypto.h"                    // for ifapi_get_profile_sig_scheme
#include "fapi_int.h"                       // for FAPI_CONTEXT, IFAPI_Impor...
#include "fapi_types.h"                     // for UINT8_ARY, NODE_STR_T
#include "fapi_util.h"                      // for ifapi_non_tpm_mode_init
#include "ifapi_helpers.h"                  // for ifapi_cleanup_policy, ifa...
#include "ifapi_io.h"                       // for ifapi_io_poll
#include "ifapi_json_deserialize.h"         // for ifapi_json_IFAPI_OBJECT_d...
#include "ifapi_keystore.h"                 // for IFAPI_OBJECT, ifapi_clean...
#include "ifapi_macros.h"                   // for goto_if_error_reset_state
#include "ifapi_policy_json_deserialize.h"  // for ifapi_json_TPMS_POLICY_de...
#include "ifapi_policy_store.h"             // for ifapi_policy_store_store_...
#include "ifapi_policy_types.h"             // for TPMS_POLICY
#include "ifapi_profiles.h"                 // for ifapi_profiles_get, IFAPI...
#include "tpm_json_deserialize.h"           // for ifapi_get_sub_object
#include "tss2_common.h"                    // for TSS2_RC, BYTE, TSS2_RC_SU...
#include "tss2_esys.h"                      // for Esys_SetTimeout, Esys_Flu...
#include "tss2_fapi.h"                      // for FAPI_CONTEXT, Fapi_Import
#include "tss2_mu.h"                        // for Tss2_MU_TPMT_SENSITIVE_Ma...
#include "tss2_policy.h"                    // for TSS2_OBJECT
#include "tss2_tcti.h"                      // for TSS2_TCTI_TIMEOUT_BLOCK
#include "tss2_tpm2_types.h"                // for TPM2B_PRIVATE, TPM2B_PUBLIC

#define LOGMODULE fapi
#include "util/log.h"                       // for goto_if_error, SAFE_FREE

/** One-Call function for Fapi_Import
 *
 * Imports a JSON encoded policy, policy template or key and stores it at the
 * given path.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] path the path to which the object is imported
 * @param[in] importData The data that is imported
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context, path or importData
 *         is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: If path does not map to a FAPI policy or key.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS: if a policy or key already exists
 *         at path.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if importData contains invalid data.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_TRY_AGAIN if an I/O operation is not finished yet and
 *         this function needs to be called again.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if a key was not found.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_FAILED if the authorization attempt fails.
 * @retval TSS2_FAPI_RC_POLICY_UNKNOWN if policy search for a certain policy digest
 *         was not successful.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 * @retval TSS2_FAPI_RC_NOT_PROVISIONED FAPI was not provisioned.
 */
TSS2_RC
Fapi_Import(
    FAPI_CONTEXT *context,
    char   const *path,
    char   const *importData)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);
    check_not_null(importData);

    r = Fapi_Import_Async(context, path, importData);
    return_if_error_reset_state(r, "Entity_Import");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_Import_Finish(context);
    } while (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN);

    return_if_error_reset_state(r, "Entity_Import");

    LOG_TRACE("finished");
    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for Fapi_Import
 *
 * Imports a JSON encoded policy, policy template or key and stores it at the
 * given path.
 *
 * Call Fapi_Import_Finish to finish the execution of this command.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] path the path to which the object is imported
 * @param[in] importData The data that is imported
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context, path or importData
 *         is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: If path does not map to a FAPI policy or key.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS: if a policy or key already exists
 *         at path.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if importData contains invalid data.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
 * @retval TSS2_FAPI_RC_NOT_PROVISIONED FAPI was not provisioned.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if a key was not found.
 */
TSS2_RC
Fapi_Import_Async(
    FAPI_CONTEXT *context,
    char   const *path,
    char   const *importData)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("path: %s", path);
    LOG_TRACE("importData: %s", importData);

    TSS2_RC r;
    json_object *jso = NULL;
    json_object *jso2;
    size_t pos = 0;
    TPMS_POLICY policy = { 0 };
    TPMA_OBJECT *attributes;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);
    check_not_null(importData);

    /* Cleanup command context. */
    memset(&context->cmd, 0, sizeof(IFAPI_CMD_STATE));

    /* Helpful alias pointers */
    IFAPI_ImportKey * command = &context->cmd.ImportKey;
    IFAPI_OBJECT *object = &command->object;
    IFAPI_EXT_PUB_KEY * extPubKey = &object->misc.ext_pub_key;
    IFAPI_DUPLICATE * keyTree = &object->misc.key_tree;
    command->private = NULL;
    command->parent_path = NULL;

    if (context->state != FAPI_STATE_INIT) {
        return_error(TSS2_FAPI_RC_BAD_SEQUENCE, "Invalid State");
    }

    command->jso_string = NULL;
    strdup_check(command->out_path, path, r, cleanup_error);
    memset(&command->object, 0, sizeof(IFAPI_OBJECT));
    memset(&command->public_templ, 0, sizeof(IFAPI_KEY_TEMPLATE));
    command->ossl_priv = NULL;
    command->profile = NULL;
    extPubKey->pem_ext_public = NULL;

    if (strncmp(importData, IFAPI_PEM_PUBLIC_STRING,
                sizeof(IFAPI_PEM_PUBLIC_STRING) - 1) == 0) {
        object->objectType = IFAPI_EXT_PUB_KEY_OBJ;
        strdup_check(extPubKey->pem_ext_public, importData, r, cleanup_error);
        extPubKey->certificate = NULL;

       TPM2_ALG_ID rsaOrEcc = ifapi_get_signature_algorithm_from_pem(
               extPubKey->pem_ext_public);
        r = ifapi_initialize_sign_public(rsaOrEcc, &extPubKey->public);
        goto_if_error(r, "Could not initialize key template", cleanup_error);

        r = ifapi_get_tpm2b_public_from_pem(extPubKey->pem_ext_public,
                                            &extPubKey->public);
        goto_if_error(r, "Convert PEM public key into TPM public key.", cleanup_error);

        extPubKey->public.publicArea.nameAlg = context->profiles.default_profile.nameAlg;

        command->new_object = *object;
        if (strncmp("/", path, 1) == 0)
            pos = 1;
        if (strncmp(&path[pos], IFAPI_PUB_KEY_DIR, strlen(IFAPI_PUB_KEY_DIR)) != 0) {
            SAFE_FREE(command->out_path);
            r = ifapi_asprintf(&command->out_path,
                               "%s%s%s", IFAPI_PUB_KEY_DIR, IFAPI_FILE_DELIM,
                               &path[pos]);
            goto_if_error(r, "Allocate path name", cleanup_error);

        }
        r = ifapi_non_tpm_mode_init(context);
        goto_if_error(r, "Initialize Import in none TPM mode", cleanup_error);

        context->state = IMPORT_KEY_WRITE_OBJECT_PREPARE;

        } else if (strncmp(importData, IFAPI_PEM_PRIVATE_KEY,
                           sizeof(IFAPI_PEM_PRIVATE_KEY) - 1) == 0 ||
                   strncmp(importData, IFAPI_PEM_ECC_PRIVATE_KEY,
                           sizeof(IFAPI_PEM_ECC_PRIVATE_KEY) - 1) == 0 ||
                   strncmp(importData, IFAPI_PEM_RSA_PRIVATE_KEY,
                           sizeof(IFAPI_PEM_RSA_PRIVATE_KEY) - 1) == 0) {

        r = ifapi_non_tpm_mode_init(context);
        goto_if_error(r, "Initialize Import in none TPM mode", cleanup_error);

        /* If the async state automata of FAPI shall be tested, then we must not set
       the timeouts of ESYS to blocking mode.
       During testing, the mssim tcti will ensure multiple re-invocations.
       Usually however the synchronous invocations of FAPI shall instruct ESYS
       to block until a result is available. */
#ifndef TEST_FAPI_ASYNC
        r = Esys_SetTimeout(context->esys, TSS2_TCTI_TIMEOUT_BLOCK);
        goto_if_error_reset_state(r, "Set Timeout to blocking", cleanup_error);
#endif /* TEST_FAPI_ASYNC */

        r = ifapi_session_init(context);
        goto_if_error(r, "Initialize Import", cleanup_error);

        attributes = &context->cmd.ImportKey.public_templ.public.publicArea.objectAttributes;
        r = ifapi_profiles_get(&context->profiles, path, &context->cmd.ImportKey.profile);
        goto_if_error2(r, "Get profile for path: %s", cleanup_error, path);

        r = ifapi_merge_profile_into_template(context->cmd.ImportKey.profile,
                                              &context->cmd.ImportKey.public_templ);
        goto_if_error(r, "Merge profile", cleanup_error);

        *attributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_USERWITHAUTH;
        context->cmd.ImportKey.ossl_priv = importData;

        /* Create session for key loading. */
        r = ifapi_get_sessions_async(context,
                                     IFAPI_SESSION_GEN_SRK | IFAPI_SESSION1,
                                     TPMA_SESSION_DECRYPT, 0);
        goto_if_error_reset_state(r, "Create sessions", cleanup_error);

        context->state = IMPORT_WAIT_FOR_SESSION;
        return TSS2_RC_SUCCESS;

    } else {
        r = ifapi_non_tpm_mode_init(context);
        goto_if_error(r, "Initialize Import in none TPM mode", cleanup_error);

        /* If the async state automata of FAPI shall be tested, then we must not set
       the timeouts of ESYS to blocking mode.
       During testing, the mssim tcti will ensure multiple re-invocations.
       Usually however the synchronous invocations of FAPI shall instruct ESYS
       to block until a result is available. */
#ifndef TEST_FAPI_ASYNC
        r = Esys_SetTimeout(context->esys, TSS2_TCTI_TIMEOUT_BLOCK);
        goto_if_error_reset_state(r, "Set Timeout to blocking", cleanup_error);
#endif /* TEST_FAPI_ASYNC */

        r = ifapi_session_init(context);
        goto_if_error(r, "Initialize Import", cleanup_error);

        /* Otherwise a JSON object has to be checked whether a key or policy is passed */
        jso = json_tokener_parse(importData);
        if (!jso) {
            goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Invalid importData.", cleanup_error);
        }

        if (ifapi_get_sub_object(jso, IFAPI_JSON_TAG_POLICY, &jso2) &&
            !(ifapi_get_sub_object(jso, IFAPI_JSON_TAG_DUPLICATE, &jso2))
            ) {
            /* Create policy object */
            r = ifapi_json_TPMS_POLICY_deserialize(jso, &policy);
            goto_if_error(r, "Serialize policy", cleanup_error);

            /* Check whether an existing object would be overwritten */
            r = ifapi_policystore_check_overwrite(&context->pstore,
                                                  command->out_path);
            goto_if_error_reset_state(r, "Check overwrite %s", cleanup_error,
                                      command->out_path);

            r = ifapi_policy_store_store_async(&context->pstore, &context->io,
                    command->out_path, &policy);
            goto_if_error_reset_state(r, "Could not open: %s", cleanup_error,
                    command->out_path);

            ifapi_cleanup_policy(&policy);

            context->state = IMPORT_KEY_WRITE_POLICY;

            r = TSS2_RC_SUCCESS;
        } else if (ifapi_get_sub_object(jso, IFAPI_JSON_TAG_OBJECT_TYPE, &jso2)) {
            /* Write key object */
            r = ifapi_json_IFAPI_OBJECT_deserialize(jso, object);
            goto_if_error(r, "Invalid object.", cleanup_error);

            switch (object->objectType) {
            case IFAPI_EXT_PUB_KEY_OBJ:
                /* Check whether an existing object would be overwritten */
                r = ifapi_keystore_check_overwrite(&context->keystore,
                        command->out_path);
                goto_if_error_reset_state(r, "Check overwrite %s", cleanup_error,
                                          command->out_path);

                /* Write json string stored in importData */
                   /* Start writing the EK to the key store */
                r = ifapi_keystore_store_async(&context->keystore, &context->io,
                        command->out_path, object);
                goto_if_error_reset_state(r, "Could not open: %sh", cleanup_error,
                        command->out_path);

                context->state = IMPORT_KEY_WRITE;
                break;

            case IFAPI_DUPLICATE_OBJ:
                r = ifapi_get_name(
                        &keyTree->public_parent.publicArea,
                        &command->parent_name);
                goto_if_error2(r, "Get parent name", cleanup_error);

                context->state = IMPORT_KEY_SEARCH;
                break;

            default:
                goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid object type",
                           cleanup_error);
                break;
            }
            command->parent_path = NULL;
        } else {
            /* A key in form of a json object with public binary blob and private binary
               blob will be imported. */
            object->objectType = IFAPI_KEY_OBJ;
            r = ifapi_json_import_IFAPI_KEY_deserialize(jso, &object->misc.key);
            goto_if_error(r, "Invalid import data for key.", cleanup_error);

            /* Compute key name from public data. */
            r = ifapi_get_name(&object->misc.key.public.publicArea,
                               &object->misc.key.name);
            goto_if_error2(r, "Get parent name", cleanup_error);


            /* Create session for key loading. */
            r = ifapi_get_sessions_async(context,
                                         IFAPI_SESSION_GEN_SRK | IFAPI_SESSION1,
                                         TPMA_SESSION_DECRYPT, 0);
            goto_if_error_reset_state(r, "Create sessions", cleanup_error);

            context->state = IMPORT_WAIT_FOR_SESSION;
        }
    }
    json_object_put(jso);
    LOG_TRACE("finished");
    return r;

cleanup_error:
    if (jso)
        json_object_put(jso);
    context->state = FAPI_STATE_INIT;
    ifapi_cleanup_policy(&policy);
    ifapi_cleanup_ifapi_object(object);
    SAFE_FREE(command->jso_string);
    SAFE_FREE(extPubKey->pem_ext_public);
    SAFE_FREE(command->out_path);
    return r;
}

/** Asynchronous finish function for Fapi_Import
 *
 * This function should be called after a previous Fapi_Import_Async.
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
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if a key was not found.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_FAILED if the authorization attempt fails.
 * @retval TSS2_FAPI_RC_POLICY_UNKNOWN if policy search for a certain policy digest
 *         was not successful.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 * @retval TSS2_FAPI_RC_NOT_PROVISIONED FAPI was not provisioned.
 * @retval TSS2_FAPI_RC_BAD_PATH if the path is used in inappropriate context
 *         or contains illegal characters.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS if the object already exists in object store.
 */
TSS2_RC
Fapi_Import_Finish(
    FAPI_CONTEXT *context)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;
    ESYS_TR session;
    size_t marshalled_sensitive_size = 0;
    size_t marshalled_length = 0;

    /* Check for NULL parameters */
    check_not_null(context);

    /* Helpful alias pointers */
    IFAPI_ImportKey * command = &context->cmd.ImportKey;
    IFAPI_OBJECT *newObject = &command->new_object;
    IFAPI_OBJECT *object = &command->object;
    IFAPI_DUPLICATE * keyTree = &object->misc.key_tree;
    ESYS_TR auth_session;

    switch (context->state) {
       statecase(context->state, IMPORT_WAIT_FOR_SESSION);
           r = ifapi_get_sessions_finish(context, &context->profiles.default_profile,
                                         context->profiles.default_profile.nameAlg);
           return_try_again(r);
           goto_if_error_reset_state(r, " FAPI create session", error_cleanup);

           r = ifapi_load_parent_keys_async(context, command->out_path);
           goto_if_error(r, "LoadKey async", error_cleanup);

           /* Profile name is first element of the explicit path list */
           char *profile_name = context->loadKey.path_list->str;
           r = ifapi_profiles_get(&context->profiles, profile_name,
                                  &context->cmd.ImportKey.profile);

           goto_if_error_reset_state(r, "Retrieving profile data", error_cleanup);

           if (object->misc.key.public.publicArea.type == TPM2_ALG_RSA)
               object->misc.key.signing_scheme
                   = context->profiles.default_profile.rsa_signing_scheme;
           else
               object->misc.key.signing_scheme
                   = context->profiles.default_profile.ecc_signing_scheme;

           fallthrough;

        statecase(context->state, IMPORT_WAIT_FOR_PARENT);
            IFAPI_OBJECT *auth_object;
            r = ifapi_load_keys_finish(context, IFAPI_FLUSH_PARENT,
                                   &context->loadKey.handle,
                                   &auth_object);
            return_try_again(r);
            goto_if_error(r, "LoadKey finish", error_cleanup);

            context->loadKey.auth_object = *auth_object;

            /* Copy private OSSL PEM key to key tree. */
            if (command->ossl_priv) {
                command->parent_object = &context->loadKey.auth_object;
                command->public_templ.public.publicArea.nameAlg =
                    command->parent_object->misc.key.public.publicArea.nameAlg;
                r = ifapi_openssl_load_private(command->ossl_priv,
                                               NULL,
                                               NULL,
                                               &context->cmd.ImportKey.public_templ.public,
                                               &keyTree->public,
                                               &command->sensitive);

                goto_if_error_reset_state(r, "Fapi load OSSL Key.", error_cleanup);

                r = Tss2_MU_TPMT_SENSITIVE_Marshal(&command->sensitive.sensitiveArea,
                                                   &keyTree->duplicate.buffer[sizeof(uint16_t)],
                                                   TPM2_MAX_DIGEST_BUFFER,
                                                   &marshalled_sensitive_size);
                goto_if_error_reset_state(r, "Fapi marshalling sensitive data of OSSL key failed.",
                                          error_cleanup);

                r = Tss2_MU_UINT16_Marshal(marshalled_sensitive_size,
                                           &keyTree->duplicate.buffer[0], sizeof(uint16_t),
                                           &marshalled_length);
                goto_if_error_reset_state(r, "Fapi marshalling size of sensitive date failed.",
                                          error_cleanup);

                keyTree->duplicate.size = marshalled_sensitive_size + sizeof(uint16_t);
                context->state = IMPORT_KEY_AUTHORIZE_PARENT;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            fallthrough;

        statecase(context->state, IMPORT_WAIT_FOR_AUTHORIZATION);
            r = ifapi_authorize_object(context, &context->loadKey.auth_object,
                                       &auth_session);
            FAPI_SYNC(r, "Authorize key.", error_cleanup);

            TPM2B_PRIVATE private;

            private.size = object->misc.key.private.size;
            memcpy(&private.buffer[0], object->misc.key.private.buffer, private.size);

            r = Esys_Load_Async(context->esys, context->loadKey.handle,
                                auth_session,
                                ENC_SESSION_IF_POLICY(auth_session),
                                ESYS_TR_NONE,
                                &private, &object->misc.key.public);
            goto_if_error(r, "Load async", error_cleanup);
            fallthrough;

        statecase(context->state, IMPORT_WAIT_FOR_KEY);
            r = Esys_Load_Finish(context->esys, &context->loadKey.handle);
            return_try_again(r);
            goto_if_error_reset_state(r, "Load", error_cleanup);

            /* Check whether object already exists in key store. */
            r = ifapi_keystore_check_overwrite(&context->keystore,
                                               command->out_path);
            goto_if_error_reset_state(r, "Check overwrite %s", error_cleanup,
                                      command->out_path);

            /* Start writing the object to the key store */
            r = ifapi_keystore_store_async(&context->keystore, &context->io,
                                           command->out_path, object);
            goto_if_error_reset_state(r, "Could not open: %sh", error_cleanup,
                                      command->out_path);
            ifapi_cleanup_ifapi_object(object);
            fallthrough;

        statecase(context->state, IMPORT_WRITE);
            /* Finish writing the key to the key store */
            r = ifapi_keystore_store_finish(&context->io);
            return_try_again(r);
            return_if_error_reset_state(r, "write_finish failed");

            if (!context->loadKey.auth_object.misc.key.persistent_handle) {
                /* Prepare Flushing of key used for authorization */
                r = Esys_FlushContext_Async(context->esys, context->loadKey.auth_object.public.handle);
                goto_if_error(r, "Flush parent", error_cleanup);
            }
            fallthrough;

        statecase(context->state, IMPORT_FLUSH_PARENT);
            if (!context->loadKey.auth_object.misc.key.persistent_handle) {
                r = Esys_FlushContext_Finish(context->esys);
                try_again_or_error_goto(r, "Flush context", error_cleanup);
            }

            /* Prepare Flushing of the loaded key */
            r = Esys_FlushContext_Async(context->esys, context->loadKey.handle);
            goto_if_error(r, "Flush key", error_cleanup);

            fallthrough;

        statecase(context->state, IMPORT_FLUSH_KEY);
            r = Esys_FlushContext_Finish(context->esys);
            try_again_or_error_goto(r, "Flush context", error_cleanup);

            fallthrough;

        statecase(context->state, IMPORT_CLEANUP);
            r = ifapi_cleanup_session(context);
            try_again_or_error_goto(r, "Cleanup", error_cleanup);

            context->state = FAPI_STATE_INIT;
            break;

        statecase(context->state, IMPORT_KEY_WRITE_POLICY);
            r = ifapi_policy_store_store_finish(&context->pstore, &context->io);
            return_try_again(r);
            return_if_error_reset_state(r, "write_finish failed");

            context->state = FAPI_STATE_INIT;
            break;

        statecase(context->state, IMPORT_KEY_WRITE);
            r = ifapi_keystore_store_finish(&context->io);
            return_try_again(r);
            return_if_error_reset_state(r, "write_finish failed");

            context->state = FAPI_STATE_INIT;
            break;

        statecase(context->state, IMPORT_KEY_SEARCH);
            r = ifapi_keystore_search_obj(&context->keystore, &context->io,
                                          &command->parent_name,
                                          &command->parent_path);
            return_try_again(r);
            goto_if_error(r, "Search Key", error_cleanup);

            context->state = IMPORT_KEY_LOAD_PARENT;
            fallthrough;

        statecase(context->state, IMPORT_KEY_LOAD_PARENT);
            r = ifapi_load_key(context, command->parent_path,
                               &command->parent_object);
            return_try_again(r);
            goto_if_error(r, "Fapi load key.", error_cleanup);

            context->state = IMPORT_KEY_AUTHORIZE_PARENT;
            fallthrough;

        statecase(context->state, IMPORT_KEY_AUTHORIZE_PARENT);
            r = ifapi_authorize_object(context, command->parent_object, &session);
            return_try_again(r);
            goto_if_error(r, "Authorize key.", error_cleanup);

            TPMT_SYM_DEF_OBJECT symmetric;
            symmetric.algorithm = TPM2_ALG_NULL;
            r = Esys_Import_Async(context->esys,
                  command->parent_object->public.handle,
                  session,
                  ENC_SESSION_IF_POLICY(session),
                  ESYS_TR_NONE,
                  NULL, &keyTree->public,
                  &keyTree->duplicate,
                  &keyTree->encrypted_seed,
                  &symmetric);
            goto_if_error(r, "Import Async", error_cleanup);

            context->state = IMPORT_KEY_IMPORT;
            fallthrough;

        statecase(context->state, IMPORT_KEY_IMPORT);
            r = Esys_Import_Finish(context->esys, &command->private);
            try_again_or_error_goto(r, "Import", error_cleanup);

            if (!command->ossl_priv) {
                /* Concatenate keyname and parent path */
                char* ipath = NULL;
                r = ifapi_asprintf(&ipath, "%s%s%s", command->parent_path,
                                   IFAPI_FILE_DELIM, command->out_path);
                goto_if_error(r, "Out of memory.", error_cleanup);

                SAFE_FREE(command->out_path);
                command->out_path = ipath;
            }

            context->state = IMPORT_KEY_WAIT_FOR_FLUSH;
            fallthrough;

        statecase(context->state, IMPORT_KEY_WAIT_FOR_FLUSH);
            if (!command->parent_object->misc.key.persistent_handle) {
                r = ifapi_flush_object(context, command->parent_object->public.handle);
                return_try_again(r);

                command->parent_object->public.handle = ESYS_TR_NONE;
                ifapi_cleanup_ifapi_object(command->parent_object);
                goto_if_error(r, "Flush key", error_cleanup);
            } else {
                ifapi_cleanup_ifapi_object(command->parent_object);
            }
            memset(newObject, 0, sizeof(IFAPI_OBJECT));
            newObject->objectType = IFAPI_KEY_OBJ;
            newObject->misc.key.public = keyTree->public;
            newObject->policy = keyTree->policy;
            newObject->misc.key.private.size = command->private->size;
            newObject->misc.key.private.buffer = &command->private->buffer[0];
            newObject->misc.key.policyInstance = NULL;
            newObject->misc.key.description = NULL;
            newObject->misc.key.certificate = NULL;
            r = ifapi_get_profile_sig_scheme(context->cmd.ImportKey.profile ?
                                             context->cmd.ImportKey.profile :
                                             &context->profiles.default_profile,
                                             &keyTree->public.publicArea,
                                             &newObject->misc.key.signing_scheme);
            goto_if_error(r, "Get signing scheme.", error_cleanup);
            fallthrough;

        statecase(context->state, IMPORT_KEY_WRITE_OBJECT_PREPARE);
            /* Perform esys serialization if necessary */
            r = ifapi_esys_serialize_object(context->esys, newObject);
            goto_if_error(r, "Prepare serialization", error_cleanup);

            /* Check whether an existing object would be overwritten */
            r = ifapi_keystore_check_overwrite(&context->keystore,
                                               command->out_path);
            goto_if_error_reset_state(r, "Check overwrite %s", error_cleanup,
                                      command->out_path);

            /* Start writing the object to the key store */
            r = ifapi_keystore_store_async(&context->keystore, &context->io,
                                           command->out_path,
                                           newObject);
            goto_if_error_reset_state(r, "Could not open: %s", error_cleanup,
                                      command->out_path);

            context->state = IMPORT_KEY_WRITE_OBJECT;
            fallthrough;

        statecase(context->state, IMPORT_KEY_WRITE_OBJECT);
            /* Finish writing the object to the key store */
            r = ifapi_keystore_store_finish(&context->io);
            return_try_again(r);
            return_if_error_reset_state(r, "write_finish failed");

            fallthrough;

        statecase(context->state, IMPORT_KEY_CLEANUP)
            r = ifapi_cleanup_session(context);
            try_again_or_error_goto(r, "Cleanup", error_cleanup);

            break;

        statecasedefault(context->state);
    }

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    if (context->esys) {
        r = Esys_SetTimeout(context->esys, 0);
        goto_if_error(r, "Set Timeout to non-blocking", error_cleanup);
    }

    context->state = FAPI_STATE_INIT;
    SAFE_FREE(command->out_path);

    /* Cleanup policy for key objects.*/
    if (newObject->objectType == IFAPI_KEY_OBJ) {
        if (newObject->policy)
            ifapi_cleanup_policy(newObject->policy);
        SAFE_FREE(newObject->policy);
    }
    SAFE_FREE(command->parent_path);
    ifapi_cleanup_ifapi_object(&command->object);
    if (command->private) {
        SAFE_FREE(command->private);
        /* Private buffer was already freed. */
        newObject->misc.key.private.buffer = NULL;
    }
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    if (context->loadKey.key_object){
        ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    }
    LOG_TRACE("finished");
    return TSS2_RC_SUCCESS;

error_cleanup:
    SAFE_FREE(command->private);
    if (newObject && newObject->objectType == IFAPI_KEY_OBJ) {
        /* Private buffer was already freed. */
        newObject->misc.key.private.buffer = NULL;
        ifapi_cleanup_ifapi_object(newObject);
    }
    SAFE_FREE(command->out_path);
    SAFE_FREE(command->parent_path);
    ifapi_cleanup_ifapi_object(&command->object);
    Esys_SetTimeout(context->esys, 0);
    ifapi_session_clean(context);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    context->state = FAPI_STATE_INIT;
    return r;
}
