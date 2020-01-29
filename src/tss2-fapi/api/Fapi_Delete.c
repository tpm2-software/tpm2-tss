/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "tss2_fapi.h"
#include "fapi_int.h"
#include "fapi_util.h"
#include "tss2_esys.h"
#include "ifapi_json_serialize.h"
#include "ifapi_json_deserialize.h"
#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"


/** One-Call function for Fapi_Delete
 *
 * Deletes a given key, policy or NV index from the system.
 *
 * @param[in, out] context The ESAPI_CONTEXT
 * @param[in] path The path to the entity that is to be deleted
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or path is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: if path does not map to a FAPI entity.
 * @retval TSS2_FAPI_RC_NOT_DELETABLE: if the entity is not deletable or the
 *         path is read-only.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_Delete(
    FAPI_CONTEXT   *context,
    char     const *path)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);

    r = Fapi_Delete_Async(context, path);
    return_if_error_reset_state(r, "Entity_Delete");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_Delete_Finish(context);
    } while ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN);

    return_if_error_reset_state(r, "Entity_Delete");

    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for Fapi_Delete
 *
 * Deletes a given key, policy or NV index from the system.

 * Call Fapi_Delete_Finish to finish the execution of this command.
 *
 * @param[in, out] context The ESAPI_CONTEXT
 * @param[in] path The path to the entity that is to be deleted
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context or path is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: if path does not map to a FAPI entity.
 * @retval TSS2_FAPI_RC_NOT_DELETABLE: if the entity is not deletable or the
 *         path is read-only.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_Delete_Async(
    FAPI_CONTEXT   *context,
    char     const *path)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("path: %s", path);

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);
    check_not_null(path);

    /* Helpful alias pointers */
    IFAPI_Entity_Delete * command = &(context->cmd.Entity_Delete);
    IFAPI_OBJECT *object = &command->object;
    IFAPI_OBJECT *authObject = &command->auth_object;

    /* Copy parameters to context for use during _Finish. */
    strdup_check(command->path, path, r, error_cleanup);

    /* List all keystore elements in the path hierarchy of the provided
       path. The last of these is the object to be deleted. */
    r = ifapi_keystore_list_all(&context->keystore, path, &command->pathlist,
                               &command->numPaths);
    return_if_error(r, "get entities.");

    command->path_idx = command->numPaths;

    if (command->numPaths == 0) {
        goto_error(r, TSS2_FAPI_RC_BAD_PATH, "No objects found.", error_cleanup);
    }

    object->objectType = IFAPI_OBJ_NONE;
    authObject->objectType = IFAPI_OBJ_NONE;

    if (ifapi_path_type_p(path, IFAPI_EXT_PATH) ||
        (ifapi_path_type_p(path, IFAPI_POLICY_PATH))) {
        /* No session will be needed these files can be deleted without
           interaction with the TPM */
        r = ifapi_non_tpm_mode_init(context);
        return_if_error(r, "Initialize Entity_Delete");

        context->state = ENTITY_DELETE_GET_FILE;
    } else {
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

        /* A TPM session will be created to enable object authorization */
        r = ifapi_session_init(context);
        return_if_error(r, "Initialize Entity_Delete");

        r = ifapi_get_sessions_async(context,
                                 IFAPI_SESSION_GENEK | IFAPI_SESSION1,
                                 0, 0);
        goto_if_error_reset_state(r, "Create sessions", error_cleanup);

        context->state = ENTITY_DELETE_WAIT_FOR_SESSION;
    }

    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;

error_cleanup:
    /* Cleanup any intermediate results and state stored in the context. */
    SAFE_FREE(command->path);
    if (Esys_FlushContext(context->esys, context->session1) != TSS2_RC_SUCCESS) {
        LOG_ERROR("Cleanup session failed.");
    }
    return r;
}


/** Asynchronous finish function for Fapi_Delete
 *
 * This function should be called after a previous Fapi_Delete_Async.
 *
 * @param [in, out] context The FAPI_CONTEXT
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
 */
TSS2_RC
Fapi_Delete_Finish(
    FAPI_CONTEXT   *context)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r;
    ESYS_TR authIndex;
    ESYS_TR auth_session;
    char *path;

    /* Check for NULL parameters */
    check_not_null(context);

    /* Helpful alias pointers */
    IFAPI_Entity_Delete * command = &(context->cmd.Entity_Delete);
    IFAPI_OBJECT *object = &command->object;
    IFAPI_OBJECT *authObject = &command->auth_object;

    switch (context->state) {
        statecase(context->state, ENTITY_DELETE_WAIT_FOR_SESSION);
            /* If a TPM object (e.g. a persistent key) was referenced, then this
               is the entry point. */
            r = ifapi_get_sessions_finish(context, &context->profiles.default_profile);
            return_try_again(r);
            goto_if_error(r, "Create FAPI session.", error_cleanup);

            fallthrough;

        statecase(context->state, ENTITY_DELETE_GET_FILE);
            /* If a non-TPM object (e.g. a policy) was referenced, then this is the
               entry point. */
            /* Use last path in the path list */
            command->path_idx -= 1;
            path = command->pathlist[command->path_idx];
            LOG_TRACE("Delete object: %s %zu", path, command->path_idx);

            if (ifapi_path_type_p(path, IFAPI_EXT_PATH)) {
                /* External keyfile can be deleted directly without TPM operations. */
                context->state = ENTITY_DELETE_FILE;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            if (ifapi_path_type_p(path, IFAPI_POLICY_PATH)) {
                /* Policy file can be deleted directly without TPM operations. */
                context->state = ENTITY_DELETE_POLICY;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            /* Load the object metadata from the keystore. */
            r = ifapi_keystore_load_async(&context->keystore, &context->io, path);
            return_if_error2(r, "Could not open: %s", path);

            fallthrough;

        statecase(context->state, ENTITY_DELETE_READ);
            /* We only end up in this path, if the referenced object requires
               TPM operations; e.g. persistent key or NV index. */
            r = ifapi_keystore_load_finish(&context->keystore, &context->io, object);
            return_try_again(r);
            return_if_error_reset_state(r, "read_finish failed");

            /* Initialize the ESYS object for the persistent key or NV Index. */
            r = ifapi_initialize_object(context->esys, object);
            goto_if_error_reset_state(r, "Initialize NV object", error_cleanup);

            if (object->objectType == IFAPI_KEY_OBJ) {
                /* If the object is a key, we jump over to ENTITY_DELETE_KEY. */
                command->is_key = true;
                context->state = ENTITY_DELETE_KEY;
                return TSS2_FAPI_RC_TRY_AGAIN;

            } else  if (object->objectType == IFAPI_NV_OBJ) {
                /* Prepare for the deletion of an NV index. */
                command->is_key = false;

                if (object->misc.nv.hierarchy == ESYS_TR_RH_OWNER) {
                    authIndex = ESYS_TR_RH_OWNER;
                    ifapi_init_hierarchy_object(authObject, authIndex);
                } else {
                    *authObject = *object;
                    authIndex = object->handle;
                }
                command->auth_index = authIndex;
                context->state = ENTITY_DELETE_AUTHORIZE_NV;
            } else {
                context->state = ENTITY_DELETE_FILE;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            fallthrough;

        statecase(context->state, ENTITY_DELETE_AUTHORIZE_NV);
            /* Authorize with the storage hierarhcy / "owner" to delete the NV index. */
            r = ifapi_authorize_object(context, authObject, &auth_session);
            return_try_again(r);
            goto_if_error(r, "Authorize NV object.", error_cleanup);

            /* Delete the NV index. */
            r = Esys_NV_UndefineSpace_Async(context->esys,
                                            command->auth_index,
                                            object->handle,
                                            auth_session,
                                            ESYS_TR_NONE,
                                            ESYS_TR_NONE);
            goto_if_error_reset_state(r, " Fapi_NV_UndefineSpace_Async", error_cleanup);

            context->state = ENTITY_DELETE_NULL_AUTH_SENT_FOR_NV;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, ENTITY_DELETE_KEY);
            if (object->misc.key.persistent_handle) {
                /* Delete the persistent handle from the TPM. */
                r = Esys_EvictControl_Async(context->esys, ESYS_TR_RH_OWNER,
                                            object->handle,
                                            context->session1,
                                            ESYS_TR_NONE, ESYS_TR_NONE,
                                            object->misc.key.persistent_handle);
                goto_if_error(r, "Evict Control", error_cleanup);
                context->state = ENTITY_DELETE_NULL_AUTH_SENT_FOR_KEY;
            } else {
                context->state = ENTITY_DELETE_FILE;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            fallthrough;

        statecase(context->state, ENTITY_DELETE_AUTH_SENT_FOR_KEY);
            fallthrough;
        statecase(context->state, ENTITY_DELETE_NULL_AUTH_SENT_FOR_KEY);
            r = Esys_EvictControl_Finish(context->esys,
                                         &command->new_object_handle);
            return_try_again(r);
            if ((r & ~TPM2_RC_N_MASK) == TPM2_RC_BAD_AUTH) {
                /* If evict control failed, we know that an owner password was set
                   and we need to re-issue the command with a password being set. */
                if (context->state == ENTITY_DELETE_NULL_AUTH_SENT_FOR_KEY) {
                    ifapi_init_hierarchy_object(authObject,
                                                TPM2_RH_OWNER);
                    r = ifapi_set_auth(context, authObject,
                                       "Owner Authorization");
                    goto_if_error_reset_state(r, "Set owner authorization", error_cleanup);

                    context->state = ENTITY_DELETE_AUTH_SENT_FOR_KEY;
                    return TSS2_FAPI_RC_TRY_AGAIN;
                }
            }
            goto_if_error_reset_state(r, "FAPI Entity_Delete", error_cleanup);

            context->state = ENTITY_DELETE_FILE;
            return TSS2_FAPI_RC_TRY_AGAIN;
            break;

        statecase(context->state, ENTITY_DELETE_AUTH_SENT_FOR_NV);
            fallthrough;
        statecase(context->state, ENTITY_DELETE_NULL_AUTH_SENT_FOR_NV);
            r = Esys_NV_UndefineSpace_Finish(context->esys);
            return_try_again(r);

            if ((r & ~TPM2_RC_N_MASK) == TPM2_RC_BAD_AUTH) {
                /* If undefine space failed, we know that an owner password was set
                   and we need to re-issue the command with a password being set. */
                if (context->state == ENTITY_DELETE_NULL_AUTH_SENT_FOR_NV) {
                    r = ifapi_set_auth(context, authObject, "Entity Delete object");
                    goto_if_error_reset_state(r, " Fapi_NV_UndefineSpace", error_cleanup);

                    r = Esys_NV_UndefineSpace_Async(context->esys,
                                                    command->auth_index,
                                                    object->handle,
                                                    context->session1,
                                                    context->session2,
                                                    ESYS_TR_NONE);
                    goto_if_error_reset_state(r, "FAPI Entity_Delete", error_cleanup);

                    context->state = ENTITY_DELETE_AUTH_SENT_FOR_NV;
                    return TSS2_FAPI_RC_TRY_AGAIN;
                }
            }
            goto_if_error_reset_state(r, "FAPI NV_UndefineSpace", error_cleanup);

            LOG_TRACE("NV Object undefined.");
            context->state = ENTITY_DELETE_FILE;
            return TSS2_FAPI_RC_TRY_AGAIN;
            break;

        statecase(context->state, ENTITY_DELETE_POLICY);
            /* This is the simple case of deleting a policy from the keystore. */
            path = command->pathlist[command->path_idx];
            LOG_TRACE("Delete: %s", path);

            r = ifapi_policy_delete(&context->pstore, path);
            goto_if_error_reset_state(r, "Could not delete: %s", error_cleanup, path);

            if (command->path_idx > 0)
                context->state = ENTITY_DELETE_GET_FILE;
            else
                context->state = ENTITY_DELETE_REMOVE_DIRS;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, ENTITY_DELETE_FILE);
            /* This is the simple case of deleting an external (pub)key from the keystore
               or we enter here after the TPM operation for the peristent key or NV index
               deletion have been performed. */
            path = command->pathlist[command->path_idx];
            LOG_TRACE("Delete: %s", path);
            ifapi_cleanup_ifapi_object(object);
            ifapi_cleanup_ifapi_object(authObject);

            /* Delete all the object's data from the keystore. */
            r = ifapi_keystore_delete(&context->keystore, path);
            goto_if_error_reset_state(r, "Could not delete: %s", error_cleanup, path);

            if (command->path_idx > 0) {
                context->state = ENTITY_DELETE_GET_FILE;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            fallthrough;

        statecase(context->state, ENTITY_DELETE_REMOVE_DIRS);
            /* For some cases, we need to remove the directory that contained the
               meta data as well. */
            r = ifapi_keystore_remove_directories(&context->keystore, command->path);
            goto_if_error(r, "Error while removing directories", error_cleanup);

            context->state = _FAPI_STATE_INIT;

            LOG_DEBUG("success");
            r = TSS2_RC_SUCCESS;
            break;

        statecasedefault(context->state);
    }

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    if (context->esys) {
        r = Esys_SetTimeout(context->esys, 0);
        goto_if_error(r, "Set Timeout to non-blocking", error_cleanup);
    }

    /* Cleanup intermediate state stored in the context. */
    SAFE_FREE(command->path);
    ifapi_cleanup_ifapi_object(authObject);
    ifapi_cleanup_ifapi_object(object);
    for (size_t i = 0; i < command->numPaths; i++) {
        SAFE_FREE(command->pathlist[i]);
    }
    SAFE_FREE(command->pathlist);
    ifapi_session_clean(context);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);

    LOG_TRACE("finsihed");
    return r;

error_cleanup:
    /* Cleanup any intermediate results and state stored in the context. */
    Esys_SetTimeout(context->esys, 0);
    ifapi_cleanup_ifapi_object(object);
    SAFE_FREE(command->path);
    for (size_t i = 0; i < command->numPaths; i++) {
        SAFE_FREE(command->pathlist[i]);
    }
    SAFE_FREE(command->pathlist);
    ifapi_session_clean(context);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    return r;
}
