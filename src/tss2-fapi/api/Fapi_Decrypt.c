/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h>           // for uint8_t
#include <stdlib.h>           // for malloc, size_t, NULL
#include <string.h>           // for memcpy, memset

#include "fapi_int.h"         // for IFAPI_Data_EncryptDecrypt, FAPI_CONTEXT
#include "fapi_util.h"        // for ifapi_authorize_object, ifapi_cleanup_s...
#include "ifapi_io.h"         // for ifapi_io_poll
#include "ifapi_keystore.h"   // for ifapi_cleanup_ifapi_object, IFAPI_OBJECT
#include "ifapi_macros.h"     // for check_not_null, return_try_again, state...
#include "ifapi_profiles.h"   // for ifapi_profiles_get, IFAPI_PROFILE, IFAP...
#include "tss2_common.h"      // for TSS2_RC, BYTE, TSS2_RC_SUCCESS, TSS2_BA...
#include "tss2_esys.h"        // for Esys_SetTimeout, ESYS_TR_NONE, Esys_Flu...
#include "tss2_fapi.h"        // for FAPI_CONTEXT, Fapi_Decrypt, Fapi_Decryp...
#include "tss2_mu.h"          // for unmarshaling of encrypted ecc data.
#include "tss2_tcti.h"        // for TSS2_TCTI_TIMEOUT_BLOCK
#include "tss2_tpm2_types.h"  // for TPM2B_PUBLIC_KEY_RSA, TPM2B_PUBLIC, TPM...

#define LOGMODULE fapi
#include "util/log.h"         // for SAFE_FREE, LOG_TRACE, goto_if_error

static TPM2_RC
unmarshal_ecc_crypt_result(const uint8_t *crypt_buf, size_t size_crypt_buf,
                           TPM2B_ECC_POINT *c1, TPM2B_MAX_BUFFER *c2,
                           TPM2B_DIGEST *c3)
{
    TSS2_RC rc;
    size_t pos = 0;
    size_t offset = 0;

    rc = Tss2_MU_TPM2B_ECC_POINT_Unmarshal(&crypt_buf[pos], size_crypt_buf,
                                           &offset, c1);
    return_if_error(rc, "Unmarshal Point.");

    pos += offset;
    offset = 0;
    rc = Tss2_MU_TPM2B_MAX_BUFFER_Unmarshal(&crypt_buf[pos], size_crypt_buf,
                                            &offset, c2);
    return_if_error(rc, "Unmarshal Max Buffer.");

    pos += offset;
    offset = 0;
    rc = Tss2_MU_TPM2B_DIGEST_Unmarshal(&crypt_buf[pos], size_crypt_buf,
                                        &offset, c3);
    return_if_error(rc, "Unmarshal Digest.");

    return rc;
}


/** One-Call function for Fapi_Decrypt
 *
 * Decrypts data that was previously encrypted with Fapi_Encrypt.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] keyPath The decryption key.
 * @param[in] cipherText The ciphertext to decrypt.
 * @param[in] cipherTextSize The size of the ciphertext to decrypt.
 * @param[out] plainText the decrypted ciphertext. May be NULL
 *             (callee-allocated)
 * @param[out] plainTextSize The size of the ciphertext in bytes. May be NULL
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or cipherText is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if can't find the key necessary to decrypt
 *         the file.
 * @retval TSS2_FAPI_RC_BAD_KEY: if the decryption key is unsuitable for the
 *         requested operation.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if the decryption fails
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
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_FAILED if the authorization attempt fails.
 * @retval TSS2_FAPI_RC_POLICY_UNKNOWN if policy search for a certain policy digest
 *         was not successful.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 * @retval TSS2_FAPI_RC_NOT_PROVISIONED FAPI was not provisioned.
 * @retval TSS2_FAPI_RC_BAD_PATH if the path is used in inappropriate context
 *         or contains illegal characters.
 */
TSS2_RC
Fapi_Decrypt(
    FAPI_CONTEXT    *context,
    char      const *keyPath,
    uint8_t   const *cipherText,
    size_t           cipherTextSize,
    uint8_t        **plainText,
    size_t          *plainTextSize)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r, r2;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(keyPath);
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

    r = Fapi_Decrypt_Async(context, keyPath, cipherText, cipherTextSize);
    return_if_error_reset_state(r, "Data_Encrypt");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_Decrypt_Finish(context, plainText, plainTextSize);
    } while (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN);

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return_if_error_reset_state(r, "Data_Decrypt");

    LOG_TRACE("finished");
    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for Fapi_Decrypt
 *
 * Decrypts data that was previously encrypted with Fapi_Encrypt.
 *
 * Call Fapi_Decrypt_Finish to finish the execution of this command.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] keyPath The decryption key.
 * @param[in] cipherText The ciphertext to decrypt
 * @param[in] cipherTextSize The size of the ciphertext to decrypt
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or cipherText is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if can't find the key necessary to decrypt
 *         the file.
 * @retval TSS2_FAPI_RC_BAD_KEY: if the decryption key is unsuitable for the
 *         requested operation.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if the decryption fails
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 */
TSS2_RC
Fapi_Decrypt_Async(
    FAPI_CONTEXT  *context,
    char    const *keyPath,
    uint8_t const *cipherText,
    size_t         cipherTextSize)
{
    LOG_TRACE("called for context:%p", context);
    LOGBLOB_TRACE(cipherText, cipherTextSize, "cipherText");

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(keyPath);
    check_not_null(cipherText);

    /* Cleanup command context. */
    memset(&context->cmd, 0, sizeof(IFAPI_CMD_STATE));

    /* Helpful alias pointers */
    IFAPI_Data_EncryptDecrypt * command = &(context->cmd.Data_EncryptDecrypt);

    /* Reset all context-internal session state information. */
    r = ifapi_session_init(context);
    return_if_error(r, "Initialize Decrypt");

    command->object_handle = ESYS_TR_NONE;
    command->plainText = NULL;

    goto_if_error(r, "Invalid cipher object.", error_cleanup);

    /* Copy parameters to context for use during _Finish. */
    uint8_t *inData = malloc(cipherTextSize);
    goto_if_null(inData, "Out of memory", r, error_cleanup);
    memcpy(inData, cipherText, cipherTextSize);
    command->in_data = inData;
    command->numBytes = cipherTextSize;
    strdup_check(command->keyPath, keyPath, r, error_cleanup);

    /* Initialize the context state for this operation. */
    context->state = DATA_DECRYPT_WAIT_FOR_PROFILE;

    LOG_TRACE("finished");
    return r;

error_cleanup:
    SAFE_FREE(command->in_data);
    SAFE_FREE(command->keyPath);
    return r;
}

/** Asynchronous finish function for Fapi_Decrypt
 *
 * This function should be called after a previous Fapi_Decrypt.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[out] plainText the decrypted ciphertext. May be NULL
 *             (callee-allocated)
 * @param[out] plainTextSize The size of the ciphertext in bytes. May be NULL
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
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
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
 * @retval TSS2_FAPI_RC_BAD_PATH if the path is used in inappropriate context
 *         or contains illegal characters.
 */
TSS2_RC
Fapi_Decrypt_Finish(
    FAPI_CONTEXT *context,
    uint8_t     **plainText,
    size_t       *plainTextSize)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;
    TPM2B_PUBLIC_KEY_RSA *tpmPlainText = NULL;
    TPM2B_MAX_BUFFER *ecc_plain_text;

    /* Check for NULL parameters */
    check_not_null(context);

    /* Helpful alias pointers */
    IFAPI_OBJECT *encKeyObject = NULL;
    IFAPI_Data_EncryptDecrypt * command = &(context->cmd.Data_EncryptDecrypt);

    switch (context->state) {
        statecase(context->state, DATA_DECRYPT_WAIT_FOR_PROFILE);
            /* Retrieve the profile for the provided key in order to get the
               encryption scheme below. */
            r = ifapi_profiles_get(&context->profiles, command->keyPath,
                                   &command->profile);
            return_try_again(r);
            goto_if_error_reset_state(r, " FAPI create session", error_cleanup);

            /* Initialize a session used for authorization and parameter encryption. */
            r = ifapi_get_sessions_async(context,
                                         IFAPI_SESSION_GEN_SRK | IFAPI_SESSION1,
                                         TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT, 0);
            goto_if_error_reset_state(r, "Create sessions", error_cleanup);

            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_SESSION);
            r = ifapi_get_sessions_finish(context, &context->profiles.default_profile,
                                          context->profiles.default_profile.nameAlg);
            return_try_again(r);
            goto_if_error_reset_state(r, " FAPI create session", error_cleanup);

            /* Load the key used for decryption. */
            r = ifapi_load_keys_async(context, command->keyPath);
            return_try_again(r);
            goto_if_error(r, "Load keys.", error_cleanup);

            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_KEY);
            r = ifapi_load_keys_finish(context, IFAPI_FLUSH_PARENT,
                                       &command->key_handle,
                                       &command->key_object);
            return_try_again(r);
            goto_if_error_reset_state(r, " Load key.", error_cleanup);

            encKeyObject = command->key_object;

            if (encKeyObject->misc.key.public.publicArea.type != TPM2_ALG_RSA &&
                 encKeyObject->misc.key.public.publicArea.type != TPM2_ALG_ECC) {
                goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid algorithm", error_cleanup);
            }
            fallthrough;

        statecase(context->state, DATA_DECRYPT_AUTHORIZE_KEY);
            /* Authorize for the key with password or policy. */
            r = ifapi_authorize_object(context, command->key_object, &command->auth_session);
            return_try_again(r);
            goto_if_error(r, "Authorize key.", error_cleanup);

            if (command->key_object->misc.key.public.publicArea.type == TPM2_ALG_ECC) {
                context->state = DATA_DECRYPT_PREPARE_ECC_ENCRYPTION;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            TPM2B_DATA null_data = {.size = 0, .buffer = {} };

            /* Copy cipher data to tpm object */
            TPM2B_PUBLIC_KEY_RSA *aux_data = (TPM2B_PUBLIC_KEY_RSA *)&context->aux_data;
            aux_data->size = context->cmd.Data_EncryptDecrypt.numBytes;
            memcpy(&aux_data->buffer[0], context->cmd.Data_EncryptDecrypt.in_data,
                   aux_data->size);

            /* Decrypt the actual data. */
            r = Esys_RSA_Decrypt_Async(context->esys,
                                       context->cmd.Data_EncryptDecrypt.key_handle,
                                       command->auth_session,
                                       ENC_SESSION_IF_POLICY(command->auth_session),
                                       ESYS_TR_NONE,
                                       aux_data,
                                       &command->profile->rsa_decrypt_scheme,
                                       &null_data);
            goto_if_error(r, "Error esys rsa decrypt", error_cleanup);

            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_RSA_DECRYPTION);
            r = Esys_RSA_Decrypt_Finish(context->esys, &tpmPlainText);
            return_try_again(r);
            goto_if_error_reset_state(r, "RSA decryption.", error_cleanup);

            /* Duplicate the decrypted plaintext for returning to the user. */
            if (plainText) {
                command->plainTextSize = tpmPlainText->size;
                command->plainText = malloc(tpmPlainText->size);
                goto_if_null(command->plainText, "Out of memory",
                             TSS2_FAPI_RC_MEMORY, error_cleanup);

                memcpy(command->plainText, &tpmPlainText->buffer[0], tpmPlainText->size);
                SAFE_FREE(tpmPlainText);
            }
            fallthrough;

        statecase(context->state, DATA_DECRYPT_PREPARE_FLUSH);

            /* Flush the used key. */
            if (!command->key_object->misc.key.persistent_handle) {
                r = Esys_FlushContext_Async(context->esys,
                                            command->key_handle);
                goto_if_error(r, "Error: FlushContext", error_cleanup);
            }

            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_FLUSH);
            if (!command->key_object->misc.key.persistent_handle) {
                r = Esys_FlushContext_Finish(context->esys);
                return_try_again(r);

                goto_if_error(r, "Error: FlushContext", error_cleanup);
            }
            command->key_handle = ESYS_TR_NONE;
            fallthrough;

        statecase(context->state, DATA_DECRYPT_CLEANUP)
            /* Cleanup session. */
            r = ifapi_cleanup_session(context);
            try_again_or_error_goto(r, "Cleanup", error_cleanup);

            if (plainText)
                *plainText = command->plainText;
            if (plainTextSize)
                *plainTextSize = command->plainTextSize;
            break;

        statecase(context->state, DATA_DECRYPT_PREPARE_ECC_ENCRYPTION)
            /* Decrypt the actual data. */
            TPM2B_ECC_POINT c1;
            TPM2B_MAX_BUFFER c2;
            TPM2B_DIGEST c3;

            r = unmarshal_ecc_crypt_result(command->in_data, command->numBytes, &c1, &c2, &c3);
            goto_if_error(r, "Unmarshal ECC cipher", error_cleanup);

            r = Esys_ECC_Decrypt_Async(context->esys,
                                       context->cmd.Data_EncryptDecrypt.key_handle,
                                       command->auth_session,
                                       ENC_SESSION_IF_POLICY(command->auth_session),
                                       ESYS_TR_NONE,
                                       &c1, &c2, &c3,
                                       &command->profile->ecc_crypt_scheme);
            goto_if_error(r, "Error esys rsa decrypt", error_cleanup);
            fallthrough;

        statecase(context->state, DATA_DECRYPT_WAIT_FOR_ECC_DECRYPTION);
            r = Esys_ECC_Decrypt_Finish(context->esys, &ecc_plain_text);
            return_try_again(r);
            goto_if_error_reset_state(r, "ECC decryption.", error_cleanup);
            if (ecc_plain_text) {
                command->plainTextSize = ecc_plain_text->size;
                command->plainText = malloc(ecc_plain_text->size);
                goto_if_null(command->plainText, "Out of memory",
                             TSS2_FAPI_RC_MEMORY, error_cleanup);

                memcpy(command->plainText, &ecc_plain_text->buffer[0],
                       ecc_plain_text->size);
                SAFE_FREE(ecc_plain_text);
            }
            context->state = DATA_DECRYPT_PREPARE_FLUSH;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecasedefault(context->state);
    }

    context->state = FAPI_STATE_INIT;

    /* Cleanup of local objects */
    SAFE_FREE(tpmPlainText);

    /* Cleanup of command related objects */
    ifapi_cleanup_ifapi_object(command->key_object);
    SAFE_FREE(command->keyPath);
    SAFE_FREE(command->in_data);

    /* Cleanup of context related objects */
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);

    LOG_TRACE("finished");
    return TSS2_RC_SUCCESS;

error_cleanup:
    /* Cleanup of local objects */
    SAFE_FREE(tpmPlainText);

    /* Cleanup of command related objects */
    ifapi_cleanup_ifapi_object(command->key_object);
    SAFE_FREE(command->keyPath);
    SAFE_FREE(command->in_data);
    SAFE_FREE(command->plainText);

    /* Cleanup of context related objects */
    if (command->key_handle != ESYS_TR_NONE)
        Esys_FlushContext(context->esys, command->key_handle);
    ifapi_session_clean(context);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    context->state = FAPI_STATE_INIT;
    return r;
}
