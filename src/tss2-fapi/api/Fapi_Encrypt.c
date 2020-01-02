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
#include "ifapi_json_serialize.h"
#include "fapi_policy.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"
#include "fapi_crypto.h"

#define IV_SIZE 16

/** One-Call function for Fapi_Encrypt
 *
 * Encrypts the provided data with a given target key.
 * If keypath is an asymmetric key and a plainText with
 * size >= TPM2_MAX_SYM_SIZE is provided, Fapi_Encrypt() will bulk-encrypt the
 * plainText with an intermediate symmetric key and then “seal” this
 * intermediate symmetric key with keyPath as a KEYEDHASH TPM object. This
 * keyPath may refer to the local TPM or to a public key of a remote TPM where
 * the KEYEDHASH can be imported. The decrypt operation performs a TPM2_Unseal.
 * ciphertext output contains a reference to the decryption key, the sealed
 * symmetric key (if any), the policy instance, and the encrypted plainText.
 *
 * If plainText has a size <= TPM2_MAX_SYM_SIZE the plainText is sealed
 * directly for keyPath.
 *
 * If encrypting for the local TPM (if keyPath is not from the external
 * hierarchy), a storage key (symmetric or asymmetric) is required as keyPath
 * (aka parent key) and the data intermediate symmetric key is created using
 * TPM2_Create() as a KEYEDHASH object.
 *
 * If encrypting for a remote TPM, an asymmetric storage key is required as
 * keyPath (aka parent key), and the data/intermediate symmetric key is
 * encrypted such that it can be used in a TPM2_Import operation.
 *
 * @param [in,out] context The FAPI_CONTEXT
 * @param [in] keyPath THe path to the encryption key
 * @param [in] policyPath The path to the policy the sealed data will be
 *        associated with. May be NULL
 * @param [in] plainText The plaintext data to encrypt
 * @param [in] plainTextSize The size of the plainText in bytes
 * @param [out] cipherText The JSON-encoded ciphertext
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context, keyPath, plainText, or
 *         cipherText is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if keyPath does not map to a FAPI key.
 * @retval TSS2_FAPI_RC_BAD_KEY: if the key at keyPath is unsuitable for
 *         encryption.
 * @retval TSS2_RC_BAD_VALUE: if plainTextSize is 0.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_Encrypt(
    FAPI_CONTEXT  *context,
    char    const *keyPath,
    char    const *policyPath,
    uint8_t const *plainText,
    size_t         plainTextSize,
    char         **cipherText)
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

    r = Fapi_Encrypt_Async(context, keyPath, policyPath, plainText, plainTextSize);
    return_if_error_reset_state(r, "Data_Encrypt");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_Encrypt_Finish(context, cipherText);
    } while ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN);

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return_if_error_reset_state(r, "Data_Encrypt");

    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for Fapi_Encrypt
 *
 * Encrypts the provided data with a given target key.
 * If keypath is an asymmetric key and a plainText with
 * size >= TPM2_MAX_SYM_SIZE is provided, Fapi_Encrypt() will bulk-encrypt the
 * plainText with an intermediate symmetric key and then “seal” this
 * intermediate symmetric key with keyPath as a KEYEDHASH TPM object. This
 * keyPath may refer to the local TPM or to a public key of a remote TPM where
 * the KEYEDHASH can be imported. The decrypt operation performs a TPM2_Unseal.
 * ciphertext output contains a reference to the decryption key, the sealed
 * symmetric key (if any), the policy instance, and the encrypted plainText.
 *
 * If plainText has a size <= TPM2_MAX_SYM_SIZE the plainText is sealed
 * directly for keyPath.
 *
 * If encrypting for the local TPM (if keyPath is not from the external
 * hierarchy), a storage key (symmetric or asymmetric) is required as keyPath
 * (aka parent key) and the data intermediate symmetric key is created using
 * TPM2_Create() as a KEYEDHASH object.
 *
 * If encrypting for a remote TPM, an asymmetric storage key is required as
 * keyPath (aka parent key), and the data/intermediate symmetric key is
 * encrypted such that it can be used in a TPM2_Import operation.
 *
 * Call Fapi_Encrypt_Finish to finish the execution of this command.
 *
 * @param [in,out] context The FAPI_CONTEXT
 * @param [in] keyPath The path to the encryption key
 * @param [in] policyPath The path to the policy the sealed data will be
 *        associated with. May be NULL
 * @param [in] plainText The plainText data to encrypt
 * @param [in] plainTextSize The size of the plainText in bytes
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context, keyPath or plainText is
 *         NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if keyPath does not map to a FAPI key.
 * @retval TSS2_FAPI_RC_BAD_KEY: if the key at keyPath is unsuitable for
 *         encryption.
 * @retval TSS2_RC_BAD_VALUE: if plainTextSize is 0.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_Encrypt_Async(
    FAPI_CONTEXT  *context,
    char    const *keyPath,
    char    const *policyPath,
    uint8_t const *plainText,
    size_t         plainTextSize)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("keyPath: %s", keyPath);
    LOG_TRACE("policyPath: %s", policyPath);
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

    /* Helpful alias pointers */
    IFAPI_Data_EncryptDecrypt * command = &(context->cmd.Data_EncryptDecrypt);

    r = ifapi_session_init(context);
    return_if_error(r, "Initialize Encrypt");

    uint8_t * inData = malloc(plainTextSize);
    goto_if_null(inData, "Out of memory", r, error_cleanup);
    memcpy(inData, plainText, plainTextSize);
    command->in_data = inData;

    strdup_check(command->keyPath, keyPath, r, error_cleanup);
    strdup_check(command->policyPath, policyPath, r, error_cleanup);

    command->in_dataSize = plainTextSize;
    command->key_handle = ESYS_TR_NONE;

    context->state = DATA_ENCRYPT_WAIT_FOR_PROFILE;
    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;
error_cleanup:
    SAFE_FREE(inData);
    SAFE_FREE(command->keyPath);
    SAFE_FREE(command->policyPath);
    return r;
}

/** Asynchronous finish function for Fapi_Encrypt
 *
 * This function should be called after a previous Fapi_Encrypt_Async.
 *
 * @param [in, out] context The FAPI_CONTEXT
 * @param [out] cipherText The JSON-encoded ciphertext
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
 */
TSS2_RC
Fapi_Encrypt_Finish(
    FAPI_CONTEXT  *context,
    char         **cipherText)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;
    uint8_t *cipher;
    size_t cipherSize;
    json_object *jso = NULL;
    const char *jso_string = NULL;
    uint8_t *data;
    size_t key_length;
    ESYS_TR auth_session;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(cipherText);

    /* Helpful alias pointers */
    IFAPI_Data_EncryptDecrypt * command = &context->cmd.Data_EncryptDecrypt;
    IFAPI_ENCRYPTED_DATA *encData = &command->enc_data;
    TPM2B_SENSITIVE_DATA * sensitiveData = &command->sym_sensitive.sensitive.data;
    TPMS_POLICY_HARNESS *policyHarness = NULL;
    const IFAPI_PROFILE *profile;
    IFAPI_OBJECT *encKeyObject;
    TPM2B_PUBLIC_KEY_RSA *tpmCipherText = NULL;

    switch (context->state) {
        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_PROFILE);
            command->outPublic = NULL;
            command->outPrivate = NULL;

            r = ifapi_get_sessions_async(context,
                                         IFAPI_SESSION_GENEK | IFAPI_SESSION1,
                                         TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT, 0);
            goto_if_error_reset_state(r, "Create sessions", error_cleanup);

            context->state = DATA_ENCRYPT_WAIT_FOR_SESSION;
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_SESSION);
            r = ifapi_profiles_get(&context->profiles, command->keyPath,
                                   &profile);
            goto_if_error_reset_state(r, " FAPI create session", error_cleanup);

            r = ifapi_get_sessions_finish(context, profile);
            return_try_again(r);

            goto_if_error_reset_state(r, " FAPI create session", error_cleanup);

            r = ifapi_load_keys_async(context, command->keyPath);
            goto_if_error(r, "Load keys.", error_cleanup);

            context->state = DATA_ENCRYPT_WAIT_FOR_KEY;
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_KEY);
            r = ifapi_load_keys_finish(context, IFAPI_FLUSH_PARENT,
                                       &command->key_handle,
                                       &command->key_object);
            return_try_again(r);

            goto_if_error_reset_state(r, " Load key.", error_cleanup);

            encKeyObject = command->key_object;

            if (encKeyObject->misc.key.public.publicArea.type == TPM2_ALG_SYMCIPHER) {
                r = ifapi_sym_encrypt_decrypt_async(context,
                                                    command->in_data,
                                                    command->in_dataSize,
                                                    TPM2_NO); /**< encrypt (not decrypt) */
                goto_if_error(r, "Symmetric encryption error.", error_cleanup);
                context-> state = DATA_ENCRYPT_WAIT_FOR_SYM_ENCRYPTION;
                return TSS2_FAPI_RC_TRY_AGAIN;
            } else if (encKeyObject->misc.key.public.publicArea.type == TPM2_ALG_RSA ||
                       encKeyObject->misc.key.public.publicArea.type == TPM2_ALG_ECC) {

                TPM2B_PUBLIC_KEY_RSA *rsa_message = (TPM2B_PUBLIC_KEY_RSA *)&context->aux_data;
                rsa_message->size =  command->in_dataSize;

                r =  ifapi_load_sym_key_template(&command->sym_template);
                goto_if_error_reset_state(r, "Load template.", error_cleanup);

                context-> state = DATA_ENCRYPT_GEN_SYM_KEY;
            }
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_GEN_SYM_KEY);
            /* Generate random key which will be sealed by currently loaded key */
            memset(&command->sym_sensitive, 0,
                   sizeof(TPM2B_SENSITIVE_CREATE));
            memset(&command->sym_outsideInfo, 0,
                   sizeof(TPM2B_DATA));
            memset(&command->sym_creationPCR, 0,
                   sizeof(TPML_PCR_SELECTION));
            sensitiveData->size = 16;
            encData->sym_key_size =
                sensitiveData->size;
            /* Generate random data for key and IV_SIZE bytes for iv */
            r = ifapi_get_random(context, encData->sym_key_size + IV_SIZE,
                                 &command->sym_key);
            return_try_again(r);
            goto_if_error(r, "Get random", error_cleanup);

            r = ifapi_get_name(&context->loadKey.auth_object.misc.key.public.publicArea,
                               &encData->key_name);
            goto_if_error(r, "Compute key name.", error_cleanup);


            memcpy(&sensitiveData->buffer[0],
                   command->sym_key,
                   sensitiveData->size);
            encData->sym_iv.size = IV_SIZE;
            memcpy(&encData->sym_iv.buffer[0],
                   &command->sym_key[encData->sym_key_size], IV_SIZE);

            SAFE_FREE(command->sym_key);
            if (!command->policyPath ||
                    strcmp(command->policyPath, "") == 0) {
                context->state = DATA_ENCRYPT_AUTHORIZE;
                return TSS2_FAPI_RC_TRY_AGAIN;
            } else {
                context-> state = DATA_ENCRYPT_CALCULATE_POLICY;
            }
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_CALCULATE_POLICY);
            r =  ifapi_calculate_policy_for_key(context,
                                                command->policyPath,
                                                &command->sym_template,
                                                &policyHarness);
            return_try_again(r);
            goto_if_error(r, "Calculate policy for sealed key", error_cleanup);

            if (policyHarness) {
                command->enc_data.sym_policy_harness = *policyHarness;
                SAFE_FREE(policyHarness);
            }

            context-> state = DATA_ENCRYPT_AUTHORIZE;
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_AUTHORIZE);
        r = ifapi_authorize_object(context, command->key_object, &auth_session);
            return_try_again(r);
            goto_if_error(r, "Authorize key.", error_cleanup);

            r = Esys_Create_Async(context->esys,
                                  command->key_handle,
                                  auth_session,
                                  ESYS_TR_NONE, ESYS_TR_NONE,
                                  &command->sym_sensitive,
                                  &command->sym_template.public,
                                  &command->sym_outsideInfo,
                                  &command->sym_creationPCR);

            goto_if_error(r, "Create_Async", error_cleanup);
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_SEAL);
            r = Esys_Create_Finish(context->esys,
                                   &command->outPrivate,
                                   &command->outPublic,
                                   NULL, NULL, NULL);
            return_try_again(r);
            goto_if_error(r, "Create_Finish", error_cleanup);

            command->enc_data.sym_public
                = *command->outPublic;
            command->enc_data.sym_private.size
                = command->outPrivate->size;
            command->enc_data.sym_private.buffer =
                &command->outPrivate->buffer[0];

            key_length = sensitiveData->size;
            data = malloc(command->in_dataSize);
            goto_if_null2(data, "Out of memory.", r, TSS2_FAPI_RC_MEMORY, error_cleanup);

            memcpy(data, command->in_data,
                   command->in_dataSize);
            r = ifapi_crypto_aes_encrypt(
                    &sensitiveData->buffer[0],
                    key_length,
                    &encData->sym_iv.buffer[0],
                    data, command->in_dataSize);
            goto_if_error(r, "AES encryption", error_cleanup);

            encData->type = IFAPI_ASYM_BULK_ENCRYPTION;
            encData->cipher.size =  command->in_dataSize;
            encData->cipher.buffer = data;
            context-> state = DATA_ENCRYPT_FLUSH_KEY;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_RSA_ENCRYPTION);
            r =  Esys_RSA_Encrypt_Finish(context->esys, &tpmCipherText);

            return_try_again(r);

            goto_if_error_reset_state(r, "RSA encryption.", error_cleanup);

            encData->type = IFAPI_ASYM_ENCRYPTION;
            encData->cipher.size = tpmCipherText->size;
            encData->cipher.buffer = malloc(encData->cipher.size);
            goto_if_null2(encData->cipher.buffer, "Out of memory", r, TSS2_FAPI_RC_MEMORY,
                          error_cleanup);

            memcpy(&encData->cipher.buffer[0], &tpmCipherText->buffer[0],
                   encData->cipher.size);

            SAFE_FREE(tpmCipherText);

            r = ifapi_get_name(&context->loadKey.auth_object.misc.key.public.publicArea,
                               &encData->key_name);
            goto_if_error(r, "Compute key name.", error_cleanup);

            context-> state = DATA_ENCRYPT_FLUSH_KEY;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_SYM_ENCRYPTION);
            r = ifapi_sym_encrypt_decrypt_finish(context, &cipher, &cipherSize,  TPM2_NO);

            return_try_again(r);
            goto_if_error_reset_state(r, "Symmetric encryption.", error_cleanup);
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_FLUSH_KEY);

            r = Esys_FlushContext_Async(context->esys,
                                        command->key_handle);
            goto_if_error(r, "Error: FlushContext", error_cleanup);
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_WAIT_FOR_FLUSH);
            r = Esys_FlushContext_Finish(context->esys);
            return_try_again(r);

            goto_if_error(r, "Error: FlushContext", error_cleanup);
            command->key_handle = ESYS_TR_NONE;
            fallthrough;

        statecase(context->state, DATA_ENCRYPT_CLEAN)
            r = ifapi_cleanup_session(context);
            try_again_or_error_goto(r, "Cleanup", error_cleanup);

            break;

        statecasedefault(context->state);
    }

    r = ifapi_json_IFAPI_ENCRYPTED_DATA_serialize(
            &command->enc_data, &jso);
    goto_if_error(r, "Error serialize FAPI cipher", error_cleanup);

    jso_string = json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY);
    goto_if_null2(jso_string, "Converting json to string", r, TSS2_FAPI_RC_MEMORY,
                  error_cleanup);

    strdup_check(*cipherText, jso_string, r, error_cleanup);
    context->state = _FAPI_STATE_INIT;

error_cleanup:
    if (command->key_handle != ESYS_TR_NONE)
        Esys_FlushContext(context->esys,  command->key_handle);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(command->key_object);
    ifapi_cleanup_policy_harness(&command->enc_data.sym_policy_harness);
    json_object_put(jso);
    SAFE_FREE(command->keyPath);
    SAFE_FREE(command->in_data);
    SAFE_FREE(command->policyPath);
    SAFE_FREE(command->out_data);
    SAFE_FREE(command->outPrivate);
    SAFE_FREE(command->outPublic);
    SAFE_FREE(encData->cipher.buffer);
    ifapi_session_clean(context);
    LOG_TRACE("finsihed");
    return r;
}
