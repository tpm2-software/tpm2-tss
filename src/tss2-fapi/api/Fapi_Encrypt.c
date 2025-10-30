/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>         // for uint8_t, PRIu16
#include <stdlib.h>           // for malloc, size_t, NULL
#include <string.h>           // for strncmp, memcpy, memset

#include "fapi_int.h"         // for IFAPI_Data_EncryptDecrypt, FAPI_CONTEXT
#include "fapi_util.h"        // for ifapi_allocate_object, ifapi_cleanup_se...
#include "ifapi_io.h"         // for ifapi_io_poll
#include "ifapi_keystore.h"   // for ifapi_cleanup_ifapi_object, IFAPI_OBJECT
#include "ifapi_macros.h"     // for check_not_null, statecase, goto_if_erro...
#include "ifapi_profiles.h"   // for IFAPI_PROFILE, ifapi_profiles_get, IFAP...
#include "tss2_common.h"      // for TSS2_RC, BYTE, TSS2_FAPI_RC_MEMORY, TSS...
#include "tss2_esys.h"        // for Esys_SetTimeout, ESYS_TR_NONE, Esys_Flu...
#include "tss2_fapi.h"        // for FAPI_CONTEXT, Fapi_Encrypt, Fapi_Encryp...
#include "tss2_tcti.h"        // for TSS2_TCTI_TIMEOUT_BLOCK
#include "tss2_mu.h"          // for mashaling the result of ECC encryption.
#include "tss2_tpm2_types.h"  // for TPM2B_PUBLIC_KEY_RSA, TPM2B_PUBLIC, TPM...

#define LOGMODULE fapi
#include "fapi_crypto.h"      // for ifapi_rsa_encrypt
#include "util/log.h"         // for LOG_TRACE, SAFE_FREE, goto_if_error

#define IV_SIZE 16

static TPM2_RC
marshal_ecc_crypt_result(TPM2B_ECC_POINT *c1, TPM2B_MAX_BUFFER *c2,
                         TPM2B_DIGEST *c3, uint8_t **crypt_buf,
                         size_t *crypt_buf_size)
{
    TSS2_RC rc;
    size_t pos = 0;
    size_t offset = 0;
    size_t size_crypt_buf = c1->size + c2->size + c3->size + 3 * (sizeof(UINT16));

    *crypt_buf = calloc(1, size_crypt_buf);

    return_if_null(*crypt_buf, "Out of Memory", TSS2_FAPI_RC_MEMORY);

    rc = Tss2_MU_TPM2B_ECC_POINT_Marshal(c1, &(*crypt_buf)[pos],
                                          size_crypt_buf,
                                          &offset);
    goto_if_error(rc, "Error Marshal Point", error);

    pos += offset;
    offset = 0;

    rc = Tss2_MU_TPM2B_MAX_BUFFER_Marshal(c2, &(*crypt_buf)[pos],
                                          size_crypt_buf,
                                          &offset);
    goto_if_error(rc, "Marshal Max Digest", error);

    pos += offset;
    offset = 0;

    rc = Tss2_MU_TPM2B_DIGEST_Marshal(c3, &(*crypt_buf)[pos],
                                      size_crypt_buf,
                                      &offset);
    goto_if_error(rc, "Marshal Digest", error);

    *crypt_buf_size = pos + offset;

    return rc;

 error:
    SAFE_FREE(*crypt_buf);
    return rc;
}

/** One-Call function for Fapi_Encrypt
 *
 * Encrypt the provided data for the target key using the TPM encryption
 * schemes as specified in the crypto profile.
 * This function does not use the TPM; i.e. works in non-TPM mode.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] keyPath THe path to the encryption key
 * @param[in] plainText The plaintext data to encrypt
 * @param[in] plainTextSize The size of the plainText in bytes
 * @param[out] cipherText The encoded cipher text.
 * @param[out] cipherTextSize The size of the encoded cipher text.
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context, keyPath, plainText, or
 *         cipherText is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if keyPath does not map to a FAPI key.
 * @retval TSS2_FAPI_RC_BAD_KEY: if the key at keyPath is unsuitable for
 *         encryption.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if plainTextSize is 0.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 * @retval TSS2_FAPI_RC_IO_ERROR if an error occurred while accessing the
 *         object store.
 * @retval TSS2_FAPI_RC_NOT_IMPLEMENTED if the encryption algorithm is not available.
 * @retval TSS2_FAPI_RC_TRY_AGAIN if an I/O operation is not finished yet and
 *         this function needs to be called again.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
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
 */
TSS2_RC
Fapi_Encrypt(
    FAPI_CONTEXT  *context,
    char    const *keyPath,
    uint8_t const *plainText,
    size_t         plainTextSize,
    uint8_t      **cipherText,
    size_t        *cipherTextSize)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r, r2;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(keyPath);
    check_not_null(plainText);
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

    r = Fapi_Encrypt_Async(context, keyPath, plainText, plainTextSize);
    return_if_error_reset_state(r, "Data_Encrypt");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_Encrypt_Finish(context, cipherText, cipherTextSize);
    } while (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN);

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return_if_error_reset_state(r, "Data_Encrypt");

    LOG_TRACE("finished");
    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for Fapi_Encrypt
 *
 * Encrypt the provided data for the target key using the TPM encryption
 * schemes as specified in the crypto profile.
 * This function does not use the TPM; i.e. works in non-TPM mode.
 *
 * Call Fapi_Encrypt_Finish to finish the execution of this command.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] keyPath The path to the encryption key
 * @param[in] plainText The plainText data to encrypt
 * @param[in] plainTextSize The size of the plainText in bytes
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context, keyPath or plainText is
 *         NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if keyPath does not map to a FAPI key.
 * @retval TSS2_FAPI_RC_BAD_KEY: if the key at keyPath is unsuitable for
 *         encryption.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if plainTextSize is 0.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 */
TSS2_RC
Fapi_Encrypt_Async(
    FAPI_CONTEXT  *context,
    char    const *keyPath,
    uint8_t const *plainText,
    size_t         plainTextSize)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("keyPath: %s", keyPath);
    if (plainText) {
        LOGBLOB_TRACE(plainText, plainTextSize, "plainText");
    } else {
        LOG_TRACE("plainText: (null) plainTextSize: %zi", plainTextSize);
    }

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(keyPath);
    check_not_null(plainText);

    /* Cleanup command context. */
    memset(&context->cmd, 0, sizeof(IFAPI_CMD_STATE));

    /* Helpful alias pointers */
    IFAPI_Data_EncryptDecrypt * command = &(context->cmd.Data_EncryptDecrypt);

    r = ifapi_session_init(context);
    return_if_error(r, "Initialize Encrypt");

    if (strncmp(keyPath, "/ext", 4) == 0) {
        r = ifapi_non_tpm_mode_init(context);
        return_if_error(r, "Initialize RSA Encrypt with OpenSSL");
    }

    /* Copy parameters to context for use during _Finish. */
    uint8_t *inData = malloc(plainTextSize);
    goto_if_null(inData, "Out of memory", r, error_cleanup);
    memcpy(inData, plainText, plainTextSize);
    command->in_data = inData;

    strdup_check(command->keyPath, keyPath, r, error_cleanup);

    command->in_dataSize = plainTextSize;
    command->key_handle = ESYS_TR_NONE;
    command->cipherText = NULL;

    /* Initialize the context state for this operation. */
    context->state = DATA_ENCRYPT_WAIT_FOR_PROFILE;
    LOG_TRACE("finished");
    return TSS2_RC_SUCCESS;

error_cleanup:
    SAFE_FREE(inData);
    SAFE_FREE(command->keyPath);
    return r;
}

/** Asynchronous finish function for Fapi_Encrypt
 *
 * This function should be called after a previous Fapi_Encrypt_Async.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[out] cipherText The encoded ciphertext
 * @param[out] cipherTextSize The size of the encoded cipher text.
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or ciphertext is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_TRY_AGAIN: if the asynchronous operation is not yet
 *         complete. Call this function again later.
 * @retval TSS2_FAPI_RC_NOT_IMPLEMENTED if the encryption algorithm is not available.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND if a FAPI object path was not found
 *         during authorization.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND if a key was not found.
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
 */
TSS2_RC
Fapi_Encrypt_Finish(
    FAPI_CONTEXT  *context,
    uint8_t      **cipherText,
    size_t        *cipherTextSize)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(cipherText);

    /* Helpful alias pointers */
    IFAPI_Data_EncryptDecrypt * command = &context->cmd.Data_EncryptDecrypt;
    TPM2B_PUBLIC *public;
    TPM2B_PUBLIC_KEY_RSA *tpmCipherText = NULL;

    switch (context->state) {
        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_PROFILE);
            /* Retrieve the profile for the provided key in order to get the
               encryption scheme below. */
            r = ifapi_profiles_get(&context->profiles, command->keyPath,
                                   &command->profile);
            return_try_again(r);
            goto_if_error_reset_state(r, " FAPI create session", error_cleanup);

            if (strncmp(command->keyPath, "/ext", 4) == 0) {
                /* Load the key for enryption from the keystore. */
                r = ifapi_keystore_load_async(&context->keystore, &context->io, command->keyPath);
                goto_if_error2(r, "Could not open: %s", error_cleanup, command->keyPath);

                context->state = DATA_ENCRYPT_WAIT_FOR_EXT_KEY;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            /* Initialize a session used for authorization and parameter encryption. */
            r = ifapi_get_sessions_async(context,
                                         IFAPI_SESSION_GEN_SRK | IFAPI_SESSION1,
                                         TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT, 0);
            goto_if_error_reset_state(r, "Create sessions", error_cleanup);

            fallthrough;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_SESSION);
            r = ifapi_get_sessions_finish(context, &context->profiles.default_profile,
                                          context->profiles.default_profile.nameAlg);
            return_try_again(r);
            goto_if_error(r, "Get session.", error_cleanup);

            /* Load the reference key by loading all of its parents starting from the SRK. */
            r = ifapi_load_keys_async(context, command->keyPath);
            goto_if_error(r, "Load keys.", error_cleanup);

            fallthrough;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_KEY);
            r = ifapi_load_keys_finish(context, IFAPI_FLUSH_PARENT,
                                       &command->key_handle,
                                       &command->key_object);
            return_try_again(r);
            goto_if_error_reset_state(r, " Load key.", error_cleanup);

            public = &command->key_object->misc.key.public;

            if (public->publicArea.type == TPM2_ALG_RSA) {
                TPM2B_DATA null_data = { .size = 0, .buffer = {} };
                TPM2B_PUBLIC_KEY_RSA *rsa_message = (TPM2B_PUBLIC_KEY_RSA *)&context->aux_data;
                size_t key_size =
                    public->publicArea.parameters.rsaDetail.keyBits / 8;
                if (context->cmd.Data_EncryptDecrypt.in_dataSize > key_size) {
                    goto_error_reset_state(r, TSS2_FAPI_RC_BAD_VALUE,
                                           "Size to big for RSA encryption.", error_cleanup);
                }
                rsa_message->size = context->cmd.Data_EncryptDecrypt.in_dataSize;
                memcpy(&rsa_message->buffer[0], context->cmd.Data_EncryptDecrypt.in_data,
                       context->cmd.Data_EncryptDecrypt.in_dataSize);

                /* Received plain text will be encrypted */
                r = Esys_TRSess_SetAttributes(context->esys, context->session1,
                                              TPMA_SESSION_CONTINUESESSION |  TPMA_SESSION_DECRYPT,
                                                  0xff);
                goto_if_error_reset_state(r, "Set session attributes.", error_cleanup);

                r = Esys_RSA_Encrypt_Async(context->esys,
                                           context->cmd.Data_EncryptDecrypt.key_handle,
                                           context->session1, ESYS_TR_NONE, ESYS_TR_NONE,
                                           rsa_message,
                                           &command->profile->rsa_decrypt_scheme,
                                           &null_data);
                goto_if_error(r, "Error esys rsa encrypt", error_cleanup);

                context-> state = DATA_ENCRYPT_WAIT_FOR_RSA_ENCRYPTION;
            } else if (public->publicArea.type == TPM2_ALG_ECC) {
                TPM2B_MAX_BUFFER *ecc_message = (TPM2B_MAX_BUFFER *)&context->aux_data;
                ecc_message->size = context->cmd.Data_EncryptDecrypt.in_dataSize;
                memcpy(&ecc_message->buffer[0], context->cmd.Data_EncryptDecrypt.in_data,
                       context->cmd.Data_EncryptDecrypt.in_dataSize);

                r = Esys_TRSess_SetAttributes(context->esys, context->session1,
                                              TPMA_SESSION_CONTINUESESSION |  TPMA_SESSION_DECRYPT,
                                              0xff);
                goto_if_error_reset_state(r, "Set session attributes.", error_cleanup);

                r = Esys_ECC_Encrypt_Async(context->esys,
                                           context->cmd.Data_EncryptDecrypt.key_handle,
                                           context->session1, ESYS_TR_NONE, ESYS_TR_NONE,
                                           ecc_message,
                                           &command->profile->ecc_crypt_scheme);
                goto_if_error(r, "Error esys ecc encrypt", error_cleanup);

                context->state = DATA_ENCRYPT_WAIT_FOR_ECC_ENCRYPTION;
                return TSS2_FAPI_RC_TRY_AGAIN;
            } else {
                goto_error(r, TSS2_FAPI_RC_NOT_IMPLEMENTED,
                           "Unsupported algorithm (%" PRIu16 ")",
                           error_cleanup, public->publicArea.type);
            }
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_RSA_ENCRYPTION);
            r = Esys_RSA_Encrypt_Finish(context->esys, &tpmCipherText);
            return_try_again(r);
            if (r == 0x00000084) {
                LOG_ERROR("The data to be encrypted might be too large. Common values are "
                          "256 bytes for no OAEP or 190 with OAEP.");
            }
            goto_if_error_reset_state(r, "RSA encryption.", error_cleanup);

            /* Return cipherTextSize if requested by the caller. */
            if (cipherTextSize)
                command->cipherTextSize = tpmCipherText->size;

            /* Duplicate the outputs for handling off to the caller. */
            command->cipherText = malloc(tpmCipherText->size);
            goto_if_null2(command->cipherText, "Out of memory", r, TSS2_FAPI_RC_MEMORY,
                          error_cleanup);

            memcpy(command->cipherText, &tpmCipherText->buffer[0], tpmCipherText->size);
            SAFE_FREE(tpmCipherText);
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_PREPARE_FLUSH)

            /* Flush the key from the TPM. */
            if (strncmp(command->keyPath, "/ext", 4) == 0 ||
                !command->key_object->misc.key.persistent_handle) {
                r = Esys_FlushContext_Async(context->esys,
                                        command->key_handle);
                goto_if_error(r, "Error: FlushContext", error_cleanup);
            }
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_FLUSH);
            if (strncmp(command->keyPath, "/ext", 4) == 0 ||
                !command->key_object->misc.key.persistent_handle) {
                r = Esys_FlushContext_Finish(context->esys);
                return_try_again(r);

                goto_if_error(r, "Error: FlushContext", error_cleanup);
            }
            command->key_handle = ESYS_TR_NONE;
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_CLEAN)
            /* Cleanup the sessions. */
            r = ifapi_cleanup_session(context);
            try_again_or_error_goto(r, "Cleanup", error_cleanup);

            *cipherText = command->cipherText;
            if (cipherTextSize)
                *cipherTextSize = command->cipherTextSize;
            break;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_EXT_KEY)
            command->key_object = ifapi_allocate_object(context);
            goto_if_null2(command->key_object, "Allocating key", r,
                          TSS2_FAPI_RC_MEMORY, error_cleanup);

            r = ifapi_keystore_load_finish(&context->keystore, &context->io,
                                   command->key_object);
            return_try_again(r);
            return_if_error_reset_state(r, "read_finish failed");

            r = ifapi_rsa_encrypt(command->key_object->misc.ext_pub_key.pem_ext_public,
                                  &command->profile->rsa_decrypt_scheme,
                                  command->in_data, command->in_dataSize,
                                  &command->cipherText, &command->cipherTextSize);

            goto_if_error_reset_state(r, "rsa encrypt with openssl.", error_cleanup);

            *cipherText = command->cipherText;
            if (cipherTextSize)
                *cipherTextSize = command->cipherTextSize;
            break;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_ECC_ENCRYPTION);
            TPM2B_ECC_POINT *c1 = NULL;
            TPM2B_MAX_BUFFER *c2 = NULL;
            TPM2B_DIGEST *c3 = NULL;

            r = Esys_ECC_Encrypt_Finish(context->esys, &c1, &c2, &c3);
            return_try_again(r);
            if (r == 0x00000084) {
                LOG_ERROR("The data to be encrypted might be too large.");
            }
            goto_if_error_reset_state(r, "ECC encryption.", error_cleanup);

            r = marshal_ecc_crypt_result(c1, c2, c3, &command->cipherText,
                                         &command->cipherTextSize);
            goto_if_error_reset_state(r, "Marshaling c1 c2 c3..", error_cleanup);

            SAFE_FREE(c1);
            SAFE_FREE(c2);
            SAFE_FREE(c3);
            context->state = DATA_ENCRYPT_PREPARE_FLUSH;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecasedefault(context->state);
    }

    context->state = FAPI_STATE_INIT;

error_cleanup:
    /* Cleanup any intermediate results and state stored in the context. */
    if (command->key_handle != ESYS_TR_NONE &&
        command->key_object && !command->key_object->misc.key.persistent_handle)
        Esys_FlushContext(context->esys,  command->key_handle);
    if (r)
        SAFE_FREE(command->cipherText);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(command->key_object);
    SAFE_FREE(tpmCipherText);
    SAFE_FREE(command->keyPath);
    SAFE_FREE(command->in_data);
    ifapi_session_clean(context);
    LOG_TRACE("finished");
    return r;
}
