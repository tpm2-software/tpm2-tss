/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "tss2_fapi.h"
#include "fapi_int.h"
#include "fapi_util.h"
#include "tss2_esys.h"
#include "fapi_crypto.h"
#include "fapi_policy.h"
#include "ifapi_policyutil_execute.h"
#include "ifapi_json_deserialize.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

/** One-Call function for Fapi_Decrypt
 *
 * Decrypts data that was previously encrypted with Fapi_Encrypt.
 *
 * @param [in, out] context The FAPI_CONTEXT
 * @param [in] cipherText The ciphertext to decrypt
 * @param [out] plainText the decrypted ciphertext. May be NULL
 *              (callee-allocated)
 * @param [out] plainTextSize The size of the ciphertext in bytes. May be NULL
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or cipherText is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if can’t find the key necessary to decrypt
 *         the file.
 * @retval TSS2_FAPI_RC_BAD_KEY: if the decryption key is unsuitable for the
 *         requested operation.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if the decryption fails
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_Decrypt(
    FAPI_CONTEXT *context,
    char   const *cipherText,
    uint8_t     **plainText,
    size_t       *plainTextSize)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r, r2;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(cipherText);

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

    r = Fapi_Decrypt_Async(context, cipherText);
    return_if_error_reset_state(r, "Data_Encrypt");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_Decrypt_Finish(context, plainText, plainTextSize);
    } while ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN);

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return_if_error_reset_state(r, "Data_Decrypt");

    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for Fapi_Decrypt
 *
 * Decrypts data that was previously encrypted with Fapi_Encrypt.
 *
 * Call Fapi_Decrypt_Finish to finish the execution of this command.
 *
 * @param [in, out] context The FAPI_CONTEXT
 * @param [in] cipherText The ciphertext to decrypt
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or cipherText is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if can’t find the key necessary to decrypt
 *         the file.
 * @retval TSS2_FAPI_RC_BAD_KEY: if the decryption key is unsuitable for the
 *         requested operation.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if the decryption fails
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_Decrypt_Async(
    FAPI_CONTEXT *context,
    char   const *cipherText)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("cipherText: %s", cipherText);

    TSS2_RC r;
    json_object *jso = NULL;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(cipherText);

    /* Helpful alias pointers */
    IFAPI_Data_EncryptDecrypt * command = &(context->cmd.Data_EncryptDecrypt);
    IFAPI_ENCRYPTED_DATA *encData = &command->enc_data;

    r = ifapi_session_init(context);
    return_if_error(r, "Initialize Decrypt");

    encData->cipher.buffer = NULL;
    command->out_data = NULL;
    jso = json_tokener_parse(cipherText);
    return_if_null(jso, "Json error.", TSS2_FAPI_RC_BAD_VALUE);
    command->object_handle = ESYS_TR_NONE;

    r = ifapi_json_IFAPI_ENCRYPTED_DATA_deserialize(jso,
            encData);
    goto_if_error(r, "Invalid cipher object.", error_cleanup);

    command->in_data =
        &encData->cipher.buffer[0];
    command->numBytes =
        encData->cipher.size;

    /* No sub path in keystore will be used (first param == NULL */
    r = ifapi_get_entities(&context->keystore, NULL,
                           &command->pathlist,
                           &command->numPaths);
    goto_if_error(r, "get entities.", error_cleanup);

    /* Start with the last path */
    command->path_idx =
        command->numPaths;

    r = ifapi_get_sessions_async(context,
                                 IFAPI_SESSION_GENEK | IFAPI_SESSION1,
                                 TPMA_SESSION_DECRYPT, 0);
    goto_if_error_reset_state(r, "Create sessions", error_cleanup);

    json_object_put(jso);
    context->state = DATA_DECRYPT_WAIT_FOR_SESSION;
    LOG_TRACE("finsihed");
    return r;

error_cleanup:
    if (jso)
        json_object_put(jso);
    SAFE_FREE(encData->cipher.buffer);

    return r;
}

/** Asynchronous finish function for Fapi_Decrypt
 *
 * This function should be called after a previous Fapi_Decrypt.
 *
 * @param [in, out] context The FAPI_CONTEXT
 * @param [out] plainText the decrypted ciphertext. May be NULL
 *              (callee-allocated)
 * @param [out] plainTextSize The size of the ciphertext in bytes. May be NULL
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context, plainText or plainTextSize
 *         is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_TRY_AGAIN: if the asynchronous operation is not yet
 *         complete. Call this function again later.
 */
TSS2_RC
Fapi_Decrypt_Finish(
    FAPI_CONTEXT *context,
    uint8_t     **plainText,
    size_t       *plainTextSize)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;
    char *path;
    UINT32 pathIdx;
    TPM2B_PUBLIC_KEY_RSA *tpmPlainText = NULL;
    TPM2B_SENSITIVE_DATA *sym_key = NULL;

    /* Check for NULL parameters */
    check_not_null(context);

    /* Helpful alias pointers */
    IFAPI_OBJECT *encKeyObject = NULL;
    IFAPI_Data_EncryptDecrypt * command = &(context->cmd.Data_EncryptDecrypt);
    IFAPI_ENCRYPTED_DATA *encData = &command->enc_data;

    switch(context->state) {
        statecase(context->state, DATA_DECRYPT_WAIT_FOR_SESSION);
            r = ifapi_get_sessions_finish(context, &context->profiles.default_profile);
            return_try_again(r);

            goto_if_error_reset_state(r, " FAPI create session", error_cleanup);
            context->state = DATA_DECRYPT_SEARCH_KEY;
            fallthrough;

        statecase(context->state, DATA_DECRYPT_SEARCH_KEY);
            r = ifapi_keystore_search_obj(&context->keystore, &context->io,
                                          &command->enc_data.key_name,
                                          &path);
            return_try_again(r);
            goto_if_error(r, "Search Key", error_cleanup);

            r = ifapi_load_keys_async(context, path);
            goto_if_error(r, "Load keys.", error_cleanup);
            LOG_TRACE("Key found.");

            SAFE_FREE(path);
            context->state = DATA_DECRYPT_WAIT_FOR_KEY;
            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_KEY);
            r = ifapi_load_keys_finish(context, IFAPI_FLUSH_PARENT,
                                       &command->key_handle,
                                       &command->key_object);
            return_try_again(r);

            goto_if_error_reset_state(r, " Load key.", error_cleanup);

            encKeyObject = command->key_object;

            /* Symmetric decryption */
            if (command->enc_data.type == IFAPI_SYM_BULK_ENCRYPTION
                    &&
                    encKeyObject->misc.key.public.publicArea.type == TPM2_ALG_SYMCIPHER) {
                r = Esys_TRSess_SetAttributes(context->esys, context->session1,
                                              TPMA_SESSION_CONTINUESESSION,
                                              0xff);

                goto_if_error_reset_state(r, "Set session attributes.", error_cleanup);

                r = ifapi_sym_encrypt_decrypt_async(context,
                                                    command->in_data,
                                                    command->in_dataSize,
                                                    TPM2_YES); /**< decrypt (not encrypt) */
                goto_if_error(r, "Symmetric decryption error.", error_cleanup);
                context-> state = DATA_DECRYPT_WAIT_FOR_SYM_ENCRYPTION;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            if (command->enc_data.type == IFAPI_ASYM_BULK_ENCRYPTION
                    &&
                (encKeyObject->misc.key.public.publicArea.type == TPM2_ALG_RSA ||
                 encKeyObject->misc.key.public.publicArea.type == TPM2_ALG_ECC)) {
                context-> state = DATA_DECRYPT_AUTHORIZE_KEY;
                return TSS2_FAPI_RC_TRY_AGAIN;
            } else {
                goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid mode", error_cleanup);
                break;
            }

        statecase(context->state, DATA_DECRYPT_AUTHORIZE_KEY);
            r = ifapi_authorize_object(context, command->key_object, &command->auth_session);
            return_try_again(r);
            goto_if_error(r, "Authorize signature key.", error_cleanup);

            TPM2B_PRIVATE private;

            private.size = encData->sym_private.size;
            memcpy(&private.buffer[0], encData->sym_private.buffer, private.size);

            r = Esys_Load_Async(context->esys, command->key_handle,
                                command->auth_session,
                                ESYS_TR_NONE, ESYS_TR_NONE,
                                &private, &encData->sym_public);
            goto_if_error(r, "Load async", error_cleanup);
            context->state = DATA_DECRYPT_WAIT_FOR_SEAL_KEY;
            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_SEAL_KEY);
            r = Esys_Load_Finish(context->esys,
                                 &command->object_handle);
            return_try_again(r);
            goto_if_error(r, "Load_Finish", error_cleanup);
            context->state = DATA_DECRYPT_FLUSH_KEY;
            fallthrough;

        statecase(context->state, DATA_DECRYPT_FLUSH_KEY);
            r = Esys_FlushContext_Async(context->esys,
                                        command->key_handle);
            goto_if_error(r, "Error: FlushContext", error_cleanup);

            context->state = DATA_DECRYPT_WAIT_FOR_FLUSH;
            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_FLUSH);
            r = Esys_FlushContext_Finish(context->esys);
            return_try_again(r);

            goto_if_error(r, "Error: FlushContext", error_cleanup);
            command->key_handle = ESYS_TR_NONE;

            if (!encData->sym_policy_harness.policy) {
                /* Object can be unsealed without authorization */
                context->state = DATA_DECRYPT_UNSEAL_OBJECT;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            r = ifapi_policyutil_execute_prepare(context,
                                                 encData->sym_public.publicArea.nameAlg,
                                                 &encData->sym_policy_harness);
            return_if_error(r, "Prepare policy execution.");

            context->policy.util_current_policy = context->policy.util_current_policy->prev;
            command->auth_session = ESYS_TR_NONE;

            fallthrough;

        statecase(context->state, DATA_DECRYPT_EXEC_POLICY);
            r = ifapi_policyutil_execute(context, &command->auth_session);
            return_try_again(r);
            goto_if_error(r, "Execute policy", error_cleanup);

            /* Clear continue session flag, so policy session will be flushed after
               authorization */
            r = Esys_TRSess_SetAttributes(context->esys, command->auth_session, 0,
                                          TPMA_SESSION_CONTINUESESSION);
            goto_if_error(r, "Esys_TRSess_SetAttributes", error_cleanup);

            fallthrough;

        statecase(context->state, DATA_DECRYPT_UNSEAL_OBJECT);
            r = Esys_Unseal_Async(context->esys,
                                  command->object_handle,
                                  command->auth_session,
                                  ESYS_TR_NONE, ESYS_TR_NONE);
            goto_if_error(r, "Error esys Unseal ", error_cleanup);
            context->state = DATA_DECRYPT_WAIT_FOR_UNSEAL;
            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_UNSEAL);
            r = Esys_Unseal_Finish(context->esys, &sym_key);
            return_try_again(r);
            goto_if_error(r, "Unseal_Finish", error_cleanup);

            r = ifapi_crypto_aes_decrypt(&sym_key->buffer[0], encData->sym_key_size,
                                         &encData->sym_iv.buffer[0],
                                         encData->cipher.buffer,
                                         encData->cipher.size);
            SAFE_FREE(sym_key);
            goto_if_error(r, "Error esys Unseal ", error_cleanup);
            if (plainText)
                *plainText =  encData->cipher.buffer;
            if (plainTextSize)
                *plainTextSize =  encData->cipher.size;

            r = Esys_FlushContext_Async(context->esys,
                                        command->object_handle);
            goto_if_error(r, "Error: FlushContext", error_cleanup);

            context->state = DATA_DECRYPT_FLUSH_SYM_OBJECT;
            fallthrough;

        statecase(context->state, DATA_DECRYPT_FLUSH_SYM_OBJECT);
            r = Esys_FlushContext_Finish(context->esys);
            return_try_again(r);
            goto_if_error(r, "Flush object", error_cleanup);

            context->state = DATA_DECRYPT_CLEANUP;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, DATA_DECRYPT_NULL_AUTH_SENT);
            /* This is used later on to differentiate two cases. see below */
            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_RSA_DECRYPTION);
            r =  Esys_RSA_Decrypt_Finish(context->esys, &tpmPlainText);

            return_try_again(r);

            /* Retry with authorization callback after trial with null auth */
            encKeyObject = command->key_object;
            if (((r & ~TPM2_RC_N_MASK) == TPM2_RC_BAD_AUTH)
                    && (encKeyObject->misc.key.public.publicArea.objectAttributes &
                        TPMA_OBJECT_NODA)
                    &&  context->state == DATA_DECRYPT_NULL_AUTH_SENT) {
                context->state = DATA_DECRYPT_WAIT_FOR_RSA_DECRYPTION;

                r = ifapi_set_auth(context, encKeyObject, "Decrypt Key");
                goto_if_error_reset_state(r, " Fapi_Decrypt", error_cleanup);

                TPM2B_PUBLIC_KEY_RSA *auxData = (TPM2B_PUBLIC_KEY_RSA *)&context->aux_data;
                TPM2B_DATA null_data = {.size = 0, .buffer = {} };
                const IFAPI_PROFILE *profile;

                pathIdx = command->path_idx;
                path = command->pathlist[pathIdx];

                r = ifapi_profiles_get(&context->profiles, path, &profile);
                goto_if_error(r, "Retrieving profiles data", error_cleanup);

                r = Esys_RSA_Decrypt_Async(context->esys,
                                           command->key_handle,
                                           context->session1, ESYS_TR_NONE, ESYS_TR_NONE,
                                           auxData,
                                           &profile->rsa_decrypt_scheme,
                                           &null_data);
                goto_if_error(r, "Error esys rsa decrypt", error_cleanup);
                SAFE_FREE(tpmPlainText);
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            goto_if_error_reset_state(r, "RSA decryption.", error_cleanup);

            if (plainTextSize)
                *plainTextSize = tpmPlainText->size;
            if (plainText) {
                *plainText = malloc(tpmPlainText->size);
                goto_if_null(*plainText, "Out of memory", TSS2_FAPI_RC_MEMORY, error_cleanup);

                memcpy(*plainText, &tpmPlainText->buffer[0], tpmPlainText->size);
            }
            SAFE_FREE(tpmPlainText);
            context-> state = DATA_DECRYPT_FLUSH_KEY;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_SYM_ENCRYPTION);
            r = ifapi_sym_encrypt_decrypt_finish(context, plainText, plainTextSize,
                                                 TPM2_YES);
            return_try_again(r);

            goto_if_error_reset_state(r, "Symmetric encryption.", error_cleanup);

            fallthrough;

        statecase(context->state, DATA_DECRYPT_CLEANUP)
            r = ifapi_cleanup_session(context);
            try_again_or_error_goto(r, "Cleanup", error_cleanup);

            break;

        statecasedefault(context->state);
    }

    context->state =  _FAPI_STATE_INIT;

    /* Cleanup of local objects */
    SAFE_FREE(tpmPlainText);

    /* Cleanup of command related objects */
    ifapi_cleanup_ifapi_object(command->key_object);
    for (size_t i = 0; i < command->numPaths; i++) {
        SAFE_FREE(command->pathlist[i]);
    }
    SAFE_FREE(command->pathlist);

    /* Cleanup of encryption data related objects */
    ifapi_cleanup_policy_harness(&encData->sym_policy_harness);
    SAFE_FREE(encData->sym_private.buffer);

    /* Cleanup of context related objects */
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);

    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;

error_cleanup:
    /* Cleanup of local objects */
    SAFE_FREE(tpmPlainText);

    /* Cleanup of command related objects */
    ifapi_cleanup_ifapi_object(command->key_object);
    ifapi_cleanup_policy_harness(&encData->sym_policy_harness);
    for (size_t i = 0; i < command->numPaths; i++) {
        SAFE_FREE(command->pathlist[i]);
    }
    SAFE_FREE(command->pathlist);

    /* Cleanup of encryption data related objects */
    SAFE_FREE(encData->cipher.buffer);
    SAFE_FREE(encData->sym_private.buffer);

    /* Cleanup of context related objects */
    if (command->key_handle != ESYS_TR_NONE)
        Esys_FlushContext(context->esys, command->key_handle);
    ifapi_session_clean(context);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);

    return r;
}
