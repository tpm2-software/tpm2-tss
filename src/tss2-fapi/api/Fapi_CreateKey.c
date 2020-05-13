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
#include "fapi_policy.h"
#include "tss2_esys.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

/** One-Call function for Fapi_CreateKey
 *
 * Creates a key inside the TPM based on the Key type, using the supplied
 * policy and authValue. The key is then stored either in the FAPI metadata
 * store or the TPM.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] path The path where the new key is stored
 * @param[in] type The type of the new key. May be NULL
 * @param[in] policyPath The path to the policy that is associated with the new
 *       key. May be NULL
 * @param[in] authValue The authorization value for the new key. May be NULL
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or path is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: if policyPath is non-NULL and does not map to
 *         a FAPI policy.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if the parent key does not map to a FAPI
 *         key.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS: if a file already exists at path.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if the keyType is non-NULL and invalid.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 * @retval TSS2_FAPI_RC_TRY_AGAIN if an I/O operation is not finished yet and
 *         this function needs to be called again.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 */
TSS2_RC
Fapi_CreateKey(
    FAPI_CONTEXT *context,
    char   const *path,
    char   const *type,
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

    r = Fapi_CreateKey_Async(context, path, type, policyPath, authValue);
    return_if_error_reset_state(r, "Key_Create");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_CreateKey_Finish(context);
    } while ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN);

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return_if_error_reset_state(r, "Key_Create");

    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for Fapi_CreateKey
 *
 * Creates a key inside the TPM based on the Key type, using the supplied
 * policy and authValue. The key is then stored either in the FAPI metadata
 * store or the TPM.
 *
 * Call Fapi_CreateKey_Finish to finish the execution of this command.
 *
 * @param[in,out] context The FAPI_CONTEXT
 * @param[in] path The path where the new key is stored
 * @param[in] type The type of the new key. May be NULL
 * @param[in] policyPath The path to the policy that is associated with the new
 *            key. May be NULL
 * @param[in] authValue The authorization value for the new key. May be NULL
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or path is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: if policyPath is non-NULL and does not map to
 *         a FAPI policy.
 * @retval TSS2_FAPI_RC_KEY_NOT_FOUND: if the parent key does not map to a FAPI
 *         key.
 * @retval TSS2_FAPI_RC_PATH_ALREADY_EXISTS: if a file already exists at path.
 * @retval TSS2_FAPI_RC_BAD_VALUE: if the keyType is non-NULL and invalid.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_NO_TPM if FAPI was initialized in no-TPM-mode via its
 *         config file.
 */
TSS2_RC
Fapi_CreateKey_Async(
    FAPI_CONTEXT *context,
    char   const *path,
    char   const *type,
    char   const *policyPath,
    char   const *authValue)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("path: %s", path);
    LOG_TRACE("type: %s", type);
    LOG_TRACE("policyPath: %s", policyPath);
    LOG_TRACE("authValue: %s", authValue);

    TSS2_RC r;
    TPMA_OBJECT *attributes;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);

    attributes = &context->cmd.Key_Create.public_templ.public.publicArea.objectAttributes;

    /* Reset all context-internal session state information. */
    r = ifapi_session_init(context);
    return_if_error(r, "Initialize CreateKey");

    /* Prepare the key creation with the authValue.
       This will also copy the input information for use during the finish call. */
    r = ifapi_key_create_prepare_auth(context, path, policyPath, authValue);
    return_if_error(r, "Key create.");

    /* Set the flags of the key to be created. If no type is given the empty-string
       default type flags are set. If no policy is given, userWithAuth flag is set. */
    r = ifapi_set_key_flags(type ? type : "",
                            (policyPath && strcmp(policyPath, "") != 0) ? true : false,
                            &context->cmd.Key_Create.public_templ);
    return_if_error(r, "Set key flags for key");

    /* If neither sign nor decrypt is set both flags will
       sign_encrypt and decrypt have to be set. */
    if (!(*attributes & TPMA_OBJECT_SIGN_ENCRYPT) &&
        !(*attributes & TPMA_OBJECT_DECRYPT)) {
        *attributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        *attributes |= TPMA_OBJECT_DECRYPT;
    }

    /* Initialize the context state for this operation. */
    context->state = KEY_CREATE;
    LOG_TRACE("finished");
    return TSS2_RC_SUCCESS;
}

/** Asynchronous finish function for Fapi_CreateKey
 *
 * This function should be called after a previous Fapi_CreateKey_Async.
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
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN if a required authorization callback
 *         is not set.
 * @retval TSS2_ESYS_RC_* possible error codes of ESAPI.
 */
TSS2_RC
Fapi_CreateKey_Finish(
    FAPI_CONTEXT *context)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);

    /* Helpful alias pointers */
    IFAPI_Key_Create * command = &context->cmd.Key_Create;

    switch (context->state) {
        statecase(context->state, KEY_CREATE);
            /* Finish the key creation inside the helper function. */
            r = ifapi_key_create(context, &command->public_templ);
            return_try_again(r);
            goto_if_error(r, "Key create", error_cleanup);

            /* Cleanup any intermediate results and state stored in the context. */
            ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
            ifapi_cleanup_ifapi_object(context->loadKey.key_object);
            ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
            context->state = _FAPI_STATE_INIT;
            LOG_TRACE("finished");
            return TSS2_RC_SUCCESS;

        statecasedefault(context->state);
    }

error_cleanup:
    /* Cleanup any intermediate results and state stored in the context. */
    context->cmd.Key_Create.state = KEY_CREATE_INIT;
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    LOG_TRACE("finished");
    return r;
}
