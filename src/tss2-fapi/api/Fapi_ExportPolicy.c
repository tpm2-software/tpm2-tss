/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "tss2_fapi.h"
#include "fapi_int.h"
#include "fapi_util.h"
#include "tss2_esys.h"
#include "fapi_policy.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

/** One-Call function for Fapi_ExportPolicy
 *
 * Exports a policy to a JSON encoded byte buffer.
 *
 * @param [in,out] context The FAPI_CONTEXT
 * @param [in] path The path to the policy that is to be exported
 * @param [out] jsonPolicy The byte buffer the JSON-encoded policy is exported
 *              to
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context, path or jsonPolicy is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: if path does not map to a FAPI policy.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_ExportPolicy(
    FAPI_CONTEXT *context,
    char   const *path,
    char        **jsonPolicy)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r, r2;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);
    check_not_null(jsonPolicy);

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

    r = Fapi_ExportPolicy_Async(context, path);
    return_if_error_reset_state(r, "PolicyExport");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_ExportPolicy_Finish(context, jsonPolicy);
    } while ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN);

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return_if_error_reset_state(r, "PolicyExport");

    return TSS2_RC_SUCCESS;

}

/** Asynchronous function for Fapi_ExportPolicy
 *
 * Exports a policy to a JSON encoded byte buffer.
 *
 * Call Fapi_ExportPolicy_Finish to finish the execution of this command.
 *
 * @param [in,out] context The FAPI_CONTEXT
 * @param [in] path The path to the policy that is to be exported
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or path is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: if path does not map to a FAPI policy.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_ExportPolicy_Async(
    FAPI_CONTEXT *context,
    char   const *path)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("path: %s", path);

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);

    /* Helpful alias pointers */
    IFAPI_ExportPolicy * command = &context->cmd.ExportPolicy;

    r = ifapi_session_init(context);
    return_if_error(r, "Initialize PolicyExport");

    if (ifapi_path_type_p(path, IFAPI_POLICY_PATH)) {
        context->state = POLICY_EXPORT_READ_POLICY;
    } else {
        context->state = POLICY_EXPORT_READ_OBJECT;
    }
    strdup_check(command->path, path, r ,error_cleanup);
    memset(&command->object, 0, sizeof(IFAPI_OBJECT));

    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;
error_cleanup:
    SAFE_FREE(command->path);
    return r;
}

/** Asynchronous finish function for Fapi_ExportPolicy
 *
 * This function should be called after a previous Fapi_ExportPolicy_Async.
 *
 * @param [in, out] context The FAPI_CONTEXT
 * @param [out] jsonPolicy The byte buffer the JSON-encoded policy is exported
 *              to
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or jsonPolicy is NULL.
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
Fapi_ExportPolicy_Finish(
    FAPI_CONTEXT *context,
    char        **jsonPolicy)
{
    LOG_TRACE("called for context:%p", context);

    TPMS_POLICY_HARNESS harness = {0};
    json_object *jso = NULL;
    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(jsonPolicy);

    /* Helpful alias pointers */
    IFAPI_ExportPolicy * command = &context->cmd.ExportPolicy;

    switch (context->state) {
        statecase(context->state, POLICY_EXPORT_READ_POLICY);
            r = ifapi_policy_store_load_async(&context->pstore, &context->io,
                                              command->path);
            goto_if_error2(r, "Can't open: %s", error_cleanup,
                    command->path);
            fallthrough;

        statecase(context->state, POLICY_EXPORT_READ_POLICY_FINISH);
            r = ifapi_policy_store_load_finish(&context->pstore, &context->io, &harness);
            return_try_again(r);
            return_if_error_reset_state(r, "read_finish failed");

            r = ifapi_json_TPMS_POLICY_HARNESS_serialize(&harness, &jso);
            goto_if_error(r, "Serialize policy", error_cleanup);

            strdup_check(*jsonPolicy,
                    json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY),
                    r, error_cleanup);

            break;
        statecase(context->state, POLICY_EXPORT_READ_OBJECT);
            memset(&command->object, 0, sizeof(IFAPI_OBJECT));
            r = ifapi_keystore_load_async(&context->keystore, &context->io,
                                          command->path);
            return_if_error2(r, "Could not open: %s", command->path);
            fallthrough;

        statecase(context->state, POLICY_EXPORT_READ_OBJECT_FINISH);
            r = ifapi_keystore_load_finish(&context->keystore, &context->io,
                                           &command->object);
            return_try_again(r);
            return_if_error_reset_state(r, "read_finish failed");

            goto_if_null2(command->object.policy_harness,
                          "Object has no policy",
                          r, TSS2_FAPI_RC_BAD_PATH, error_cleanup);

            r = ifapi_json_TPMS_POLICY_HARNESS_serialize(context->
                cmd.ExportPolicy.object.policy_harness, &jso);
            goto_if_error(r, "Serialize policy", error_cleanup);

            strdup_check(*jsonPolicy,
                    json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY),
                    r, error_cleanup);
            break;

        statecasedefault(context->state);
    }
    goto_if_null2(*jsonPolicy, "Out of memory.", r, TSS2_FAPI_RC_MEMORY, error_cleanup);

    context->state = _FAPI_STATE_INIT;
    if (jso)
        json_object_put(jso);
    ifapi_cleanup_ifapi_object(&command->object);
    ifapi_cleanup_policy_harness(&harness);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    SAFE_FREE(command->path);
    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;

error_cleanup:
    if (command->object.objectType)
        ifapi_cleanup_ifapi_object(&command->object);
    if (jso)
        json_object_put(jso);
    ifapi_cleanup_policy_harness(&harness);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    SAFE_FREE(command->path);
    context->state = _FAPI_STATE_INIT;
    return r;
}
