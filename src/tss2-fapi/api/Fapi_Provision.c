/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "fapi_util.h"
#include "tss2_tcti.h"
#include "tss2_esys.h"
#include "tss2_fapi.h"
#include "fapi_int.h"
#include "fapi_crypto.h"
#include "fapi_policy.h"
#include "ifapi_get_intl_cert.h"

#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

#define EK_CERT_RANGE (0x01c07fff)

/** One-Call function for the initial FAPI provisioning.
 *
 * Provisions a TSS with its TPM. This includes the setting of important passwords
 * and policy settings as well as the readout of the EK and its certificate and
 * the initialization of the system-wide keystore.
 *
 * @param [in,out] context The FAPI_CONTEXT.
 * @param [in] authValueEh The authorization value for the endorsement
 *             hierarchy. May be NULL
 * @param [in] authValueSh The authorization value for the storage hierarchy.
 *             Should be NULL
 * @param [in] authValueLockout The authorization value for lockout.
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: if policyPathEh or policyPathSh do not map to
 *         a FAPI policy.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_NO_CERT: if no certificate was found for the computed EK.
 * @retval TSS2_FAPI_RC_BAD_KEY: if public key of the EK does not match the
           configured certificate or the configured fingerprint does not match
           the computed EK.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_Provision(
    FAPI_CONTEXT *context,
    char   const *authValueEh,
    char   const *authValueSh,
    char   const *authValueLockout)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r, r2;

    /* Check for NULL parameters */
    check_not_null(context);

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

    r = Fapi_Provision_Async(context, authValueEh, authValueSh, authValueLockout);
    return_if_error_reset_state(r, "Provision");

    do {
        /* We wait for file I/O to be ready if the FAPI state automata
           are in a file I/O state. */
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");

        /* Repeatedly call the finish function, until FAPI has transitioned
           through all execution stages / states of this invocation. */
        r = Fapi_Provision_Finish(context);
    } while ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN);

    /* Reset the ESYS timeout to non-blocking, immediate response. */
    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return_if_error_reset_state(r, "Provision");

    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for the initial FAPI provisioning.
 *
 * Provisions a TSS with its TPM. This includes the setting of important passwords
 * and policy settings as well as the readout of the EK and its certificate and
 * the initialization of the system-wide keystore.
 *
 * Call Fapi_Provision_Finish to finish the execution of this command.
 *
 * @param [in,out] context The FAPI_CONTEXT.
 * @param [in] authValueEh The authorization value for the endorsement
 *             hierarchy. May be NULL
 * @param [in] authValueSh The authorization value for the storage hierarchy.
 *             Should be NULL
 * @param [in] authValueLockout The authorization value for lockout.
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_PATH: if policyPathEh or policyPathSh do not map to
 *         a FAPI policy.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 */
TSS2_RC
Fapi_Provision_Async(
    FAPI_CONTEXT *context,
    char const *authValueEh,
    char const *authValueSh,
    char const *authValueLockout)
{
    LOG_TRACE("called for context:%p", context);
    LOG_TRACE("authValueEh: %s", authValueEh);
    LOG_TRACE("authValueSh: %s", authValueSh);
    LOG_TRACE("authValueLockout: %s", authValueLockout);

    TSS2_RC r;

    /* Check for NULL parameters */
    check_not_null(context);

    /* Helpful alias pointers */
    IFAPI_Provision * command = &context->cmd.Provision;

    r = ifapi_session_init(context);
    goto_if_error(r, "Initialize Provision", end);

    strdup_check(command->authValueLockout, authValueLockout, r, end);
    strdup_check(command->authValueEh, authValueEh, r, end);
    strdup_check(command->authValueSh, authValueSh, r, end);
    context->ek_handle = ESYS_TR_NONE;
    context->srk_handle = ESYS_TR_NONE;
    command->cert_nv_idx = MIN_EK_CERT_HANDLE;
    command->capabilityData = NULL;

    context->state = PROVISION_READ_PROFILE;
    LOG_TRACE("finsihed");
    return TSS2_RC_SUCCESS;
end:
    SAFE_FREE(command->authValueLockout);
    SAFE_FREE(command->authValueEh);
    SAFE_FREE(command->authValueSh);
    return r;
}

/** Asynchronous finish function for Fapi_Provision
 *
 * This function should be called after a previous Fapi_Provision_Async.
 *
 * @param [in, out] context The FAPI_CONTEXT
 *
 * @retval TSS2_RC_SUCCESS: if the function call was a success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if context is NULL.
 * @retval TSS2_FAPI_RC_BAD_CONTEXT: if context corruption is detected.
 * @retval TSS2_FAPI_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_FAPI_RC_NO_CERT: if no certificate was found for the computed EK.
 * @retval TSS2_FAPI_RC_BAD_KEY: if public key of the EK does not match the
           configured certificate or the configured fingerprint does not match
           the computed EK.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be saved.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_TRY_AGAIN: if the asynchronous operation is not yet
 *         complete. Call this function again later.
 */
TSS2_RC
Fapi_Provision_Finish(FAPI_CONTEXT *context)
{
    LOG_TRACE("called for context:%p", context);

    TSS2_RC r = TSS2_RC_SUCCESS;
    TPM2B_NV_PUBLIC *nvPublic = NULL;
    uint8_t *certData = NULL;
    size_t certSize;
    TPMI_YES_NO moreData;
    size_t hash_size;
    TPMI_ALG_HASH hash_alg;
    TPM2B_DIGEST ek_fingerprint;

    /* Check for NULL parameters */
    check_not_null(context);

    /* Helpful alias pointers */
    IFAPI_Provision * command = &context->cmd.Provision;
    IFAPI_OBJECT *hierarchy = &command->hierarchy;
    TPMS_CAPABILITY_DATA **capabilityData = &command->capabilityData;
    IFAPI_NV_Cmds * nvCmd = &context->nv_cmd;
    IFAPI_OBJECT * pkeyObject = &context->createPrimary.pkey_object;
    IFAPI_KEY * pkey = &pkeyObject->misc.key;
    IFAPI_PROFILE * defaultProfile = &context->profiles.default_profile;

    switch (context->state) {
        statecase(context->state, PROVISION_READ_PROFILE);
            command->root_crt = NULL;
            r = ifapi_set_key_flags(defaultProfile->srk_template,
                    context->profiles.default_profile.srk_policy ? true : false,
                    &command->public_templ);
            goto_if_error(r, "Set key flags for SRK", error_cleanup);

            r = ifapi_merge_profile_into_template(&context->profiles.default_profile,
                    &command->public_templ);
            goto_if_error(r, "Merging profile and template", error_cleanup);

            r = Esys_DictionaryAttackParameters_Async(context->esys, ESYS_TR_RH_LOCKOUT,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    defaultProfile->newMaxTries, defaultProfile->newRecoveryTime,
                    defaultProfile->lockoutRecovery);
            goto_if_error(r, "Error Esys_DictionaryAttackParameters",
                          error_cleanup);
            fallthrough;

        statecase(context->state, PROVISION_WRITE_LOCKOUT_PARAM);
            r = Esys_DictionaryAttackParameters_Finish(context->esys);
            return_try_again(r);
            goto_if_error_reset_state(r, "DictionaryAttackParameters_Finish",
                    error_cleanup);

            r = Esys_GetCapability_Async(context->esys,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_PCRS, 0, 1);
            goto_if_error(r, "Esys_GetCapability_Async", error_cleanup);

            fallthrough;

        statecase(context->state, PROVISION_WAIT_FOR_GET_CAP1);
            r = Esys_GetCapability_Finish(context->esys, &moreData, capabilityData);
            return_try_again(r);
            goto_if_error_reset_state(r, "GetCapablity_Finish", error_cleanup);

            TPML_PCR_SELECTION pcr_capability = (*capabilityData)->data.assignedPCR;
            r = ifapi_check_profile_pcr_selection(&defaultProfile->pcr_selection,
                    &pcr_capability);
            goto_if_error(r, "Invalid PCR selection in profile.", error_cleanup);

            SAFE_FREE(*capabilityData);
            fallthrough;

        statecase(context->state, PROVISION_INIT_SRK);
            /* Clear key object for the primary to be created */
            memset(pkey, 0, sizeof(IFAPI_KEY));
            r = ifapi_init_primary_async(context, TSS2_SRK);
            goto_if_error(r, "Initialize primary", error_cleanup);

            context->state =  PROVISION_AUTH_SRK_NO_AUTH_SENT;
            fallthrough;

        statecase(context->state, PROVISION_AUTH_SRK_AUTH_SENT);
            fallthrough;

        statecase(context->state, PROVISION_AUTH_SRK_NO_AUTH_SENT);
            r = ifapi_init_primary_finish(context, TSS2_SRK);
            return_try_again(r);
            goto_if_error(r, "Init primary finish.", error_cleanup);

            if (command->public_templ.persistent_handle) {
                /* Assign found handle to object */
                pkey->persistent_handle = command->public_templ.persistent_handle;
                ifapi_init_hierarchy_object(hierarchy, ESYS_TR_RH_OWNER);
                r = Esys_EvictControl_Async(context->esys, hierarchy->handle,
                    pkeyObject->handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    pkey->persistent_handle);
                goto_if_error(r, "Error Esys EvictControl", error_cleanup);
                context->state = PROVISION_WAIT_FOR_SRK_PERSISTENT;
                return TSS2_FAPI_RC_TRY_AGAIN;
            } else {
                context->state = PROVISION_SRK_WRITE_PREPARE;
            }

            context->state = PROVISION_SRK_WRITE_PREPARE;
            fallthrough;

        statecase(context->state, PROVISION_SRK_WRITE_PREPARE);
            pkeyObject->objectType = IFAPI_KEY_OBJ;
            pkeyObject->system = command->public_templ.system;

            /* Perform esys serialization if necessary */
            r = ifapi_esys_serialize_object(context->esys, pkeyObject);
            goto_if_error(r, "Prepare serialization", error_cleanup);

            /* Start writing the SRK to the key store */
            r = ifapi_keystore_store_async(&context->keystore, &context->io, "HS/SRK",
                    pkeyObject);
            goto_if_error_reset_state(r, "Could not open: %sh", error_cleanup, "HS/SRK");
            context->state = PROVISION_SRK_WRITE;
            fallthrough;

        statecase(context->state, PROVISION_SRK_WRITE);
            /* Finish writing the SRK to the key store */
            r = ifapi_keystore_store_finish(&context->keystore, &context->io);
            return_try_again(r);
            goto_if_error_reset_state(r, "write_finish failed", error_cleanup);

            /* Clean objects used for SRK computation */
            ifapi_cleanup_ifapi_object(pkeyObject);
            memset(&command->public_templ, 0, sizeof(IFAPI_KEY_TEMPLATE));

            r = ifapi_set_key_flags(defaultProfile->ek_template,
                     context->profiles.default_profile.ek_policy ? true : false,
                     &command->public_templ);
            goto_if_error(r, "Set key flags for SRK", error_cleanup);

            r = ifapi_merge_profile_into_template(&context->profiles.default_profile,
                    &command->public_templ);
            goto_if_error(r, "Merging profile", error_cleanup);

            /* Clear key object for the primary to be created */
            memset(pkey, 0, sizeof(IFAPI_KEY));
            r = ifapi_init_primary_async(context, TSS2_EK);
            goto_if_error(r, "Initialize primary", error_cleanup);

            context->state = PROVISION_AUTH_EK_NO_AUTH_SENT;
            fallthrough;

        statecase(context->state, PROVISION_AUTH_EK_AUTH_SENT);
            fallthrough;

        statecase(context->state, PROVISION_AUTH_EK_NO_AUTH_SENT);
            r = ifapi_init_primary_finish(context, TSS2_EK);
            return_try_again(r);
            goto_if_error(r, "Init primary finish", error_cleanup);

            ifapi_init_hierarchy_object(hierarchy, ESYS_TR_RH_OWNER);
            if (command->public_templ.persistent_handle) {
                pkey->persistent_handle = command->public_templ.persistent_handle;
                r = Esys_EvictControl_Async(context->esys, hierarchy->handle,
                        pkeyObject->handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                        ESYS_TR_NONE, pkey->persistent_handle);
                goto_if_error(r, "Error Esys EvictControl", error_cleanup);
                context->state = PROVISION_WAIT_FOR_EK_PERSISTENT;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            fallthrough;

        statecase(context->state, PROVISION_INIT_GET_CAP2);
            if (context->config.ek_cert_less == TPM2_YES) {
                /* Skip certificate validation. */
                context->state = PROVISION_EK_WRITE_PREPARE;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            /* Check whether fingerprint for EK is defined in config file. */
            hash_alg = context->config.ek_fingerprint.hashAlg;
            if (hash_alg) {
                LOG_DEBUG("Only fingerprint check for EK.");
                if (!(hash_size =ifapi_hash_get_digest_size(hash_alg))) {
                    goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                               "Unsupported hash algorithm (%" PRIu16 ")", error_cleanup,
                               hash_alg);
                }
                r = ifapi_get_tpm_key_fingerprint(&pkeyObject->misc.key.public, hash_alg,
                                                  &ek_fingerprint);
                goto_if_error_reset_state(r, "Get fingerprint of EK", error_cleanup);

                if (hash_size != ek_fingerprint.size ||
                    memcmp(&context->config.ek_fingerprint.digest, &ek_fingerprint.buffer[0],
                           hash_size) != 0) {
                    goto_error(r, TSS2_FAPI_RC_BAD_KEY,
                               "Fingerprint of EK not equal to fingerprint in config file.",
                               error_cleanup);
                }
                /* The fingerprint was found no further certificate processing needed. */
                context->state = PROVISION_EK_WRITE_PREPARE;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            /* Check whether EK certificate has to be retrieved */
            if (context->config.ek_cert_file) {
                size_t cert_size;
                TPM2B_PUBLIC public_key;

                r = ifapi_get_curl_buffer((unsigned char *)context->config.ek_cert_file,
                                          (unsigned char **)&command->pem_cert, &cert_size);
                goto_if_error_reset_state(r, "Get certificate", error_cleanup);

                /* Compare public key of certificate with public data of EK */

                r = ifapi_get_public_from_pem_cert(command->pem_cert, &public_key);
                goto_if_error_reset_state(r, "Get public key from pem certificate",
                                          error_cleanup);

                if (ifapi_cmp_public_key(&pkeyObject->misc.key.public, &public_key)) {
                    /* The retrieved certificate will be written to keystore,
                       no further certificate processing needed. */
                    context->state = PROVISION_EK_WRITE_PREPARE;
                    return TSS2_FAPI_RC_TRY_AGAIN;
                }
                goto_error(r, TSS2_FAPI_RC_BAD_KEY,
                           "Public key of EK does not match certificate.",
                           error_cleanup);
            }

            r = Esys_GetCapability_Async(context->esys,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_HANDLES,
                    MIN_EK_CERT_HANDLE, TPM2_MAX_CAP_HANDLES);
            goto_if_error(r, "Esys_GetCapability_Async", error_cleanup);

            fallthrough;

        statecase(context->state, PROVISION_WAIT_FOR_GET_CAP2);
            r = Esys_GetCapability_Finish(context->esys, &moreData, capabilityData);
            return_try_again(r);
            goto_if_error_reset_state(r, "GetCapablity_Finish", error_cleanup);

            if ((*capabilityData)->data.handles.count == 0) {
                Esys_Free(*capabilityData);
                context->state = PROVISION_CHECK_FOR_VENDOR_CERT;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            command->capabilityData = *capabilityData;
            command->cert_count = (*capabilityData)->data.handles.count;

            /* Filter out NV handles beyond the EK cert range */
            for (size_t i = 0; i < command->cert_count; i++) {
                if (command->capabilityData->data.handles.handle[i] > EK_CERT_RANGE) {
                    command->cert_count = i;
                }
            }

            if (command->cert_count == 0) {
                Esys_Free(command->capabilityData);
                command->capabilityData = NULL;
                context->state = PROVISION_CHECK_FOR_VENDOR_CERT;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            fallthrough;

        statecase(context->state, PROVISION_GET_CERT_NV);
            command->cert_nv_idx
                = command->capabilityData->data.handles.handle[command->cert_count-1];

            if ((command->cert_nv_idx % 2) || /**< Certificates will be stored at even address */
                command->cert_nv_idx == 0x01c00004 || /**< RSA template */
                command->cert_nv_idx == 0x01c0000c) { /**< ECC template */
                if (command->cert_count > 1) {
                    command->cert_count -= 1;
                    /* Check next certificate */
                    context->state = PROVISION_GET_CERT_NV;
                    return TSS2_FAPI_RC_TRY_AGAIN;
                } else {
                    context->state = PROVISION_EK_WRITE_PREPARE;
                    return TSS2_FAPI_RC_TRY_AGAIN;
                }
            }
            ifapi_init_hierarchy_object(&nvCmd->auth_object, TPM2_RH_OWNER);

            r = Esys_TR_FromTPMPublic_Async(context->esys, command->cert_nv_idx,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
            goto_if_error_reset_state(r, "Esys_TR_FromTPMPublic_Async", error_cleanup);

            context->state = PROVISION_GET_CERT_NV_FINISH;
            fallthrough;

        statecase(context->state, PROVISION_GET_CERT_NV_FINISH);
            r = Esys_TR_FromTPMPublic_Finish(context->esys,
                    &command->esys_nv_cert_handle);
            return_try_again(r);
            goto_if_error_reset_state(r, "TR_FromTPMPublic_Finish", error_cleanup);

            /* Read public to get size of certificate */
            r = Esys_NV_ReadPublic_Async(context->esys, command->esys_nv_cert_handle,
                     ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
            goto_if_error_reset_state(r, "Esys_NV_ReadPublic_Async", error_cleanup);

            context->state = PROVISION_GET_CERT_READ_PUBLIC;
            fallthrough;

        statecase(context->state, PROVISION_GET_CERT_READ_PUBLIC);
            r = Esys_NV_ReadPublic_Finish(context->esys, &nvPublic, NULL);
            return_try_again(r);

            goto_if_error(r, "Error: nv read public", error_cleanup);

            /* TPMA_NV_NO_DA is set for NV certificate */
            nvCmd->nv_object.misc.nv.public.nvPublic.attributes = TPMA_NV_NO_DA;

            /* Prepare context for nv read */
            nvCmd->data_idx = 0;
            nvCmd->auth_index = ESYS_TR_RH_OWNER;
            nvCmd->numBytes = nvPublic->nvPublic.dataSize;
            nvCmd->esys_handle = command->esys_nv_cert_handle;
            nvCmd->offset = 0;
            command->pem_cert = NULL;
            context->session1 = ESYS_TR_PASSWORD;
            context->session2 = ESYS_TR_NONE;
            nvCmd->nv_read_state = NV_READ_INIT;
            memset(&nvCmd->nv_object, 0, sizeof(IFAPI_OBJECT));
            SAFE_FREE(nvPublic);

            context->state = PROVISION_READ_CERT;
            fallthrough;

        statecase(context->state, PROVISION_READ_CERT);
            TPM2B_PUBLIC public_key;
            char * root_ca_file;
            r = ifapi_nv_read(context, &certData, &certSize);
            return_try_again(r);
            goto_if_error_reset_state(r, " FAPI NV_Read", error_cleanup);

            //TODO check even and not template
            r = ifapi_cert_to_pem(certData, certSize, &command->pem_cert,
                                  &command->cert_key_type, &public_key);
            SAFE_FREE(certData);
            goto_if_error(r, "Convert certificate to pem.", error_cleanup);

            if (ifapi_cmp_public_key(&pkeyObject->misc.key.public, &public_key)) {
                context->state = PROVISION_PREPARE_READ_ROOT_CERT;
                return TSS2_FAPI_RC_TRY_AGAIN;
            } else {
                /* Certificate not appropriate for current EK key type */
                command->cert_count -= 1;
                SAFE_FREE(command->pem_cert);
                if (command->cert_count > 0) {
                    /* Check next certificate */
                    context->state = PROVISION_GET_CERT_NV;
                    return TSS2_FAPI_RC_TRY_AGAIN;
                }
            }

            goto_error(r, TSS2_FAPI_RC_NO_CERT, "No EK certificate found.",
                       error_cleanup);

        statecase(context->state, PROVISION_PREPARE_READ_ROOT_CERT);
            /* Prepare reading of root certificate. */
            root_ca_file = getenv("FAPI_TEST_ROOT_CERT");
            if (!root_ca_file) {
                context->state = PROVISION_EK_CHECK_CERT;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            r = ifapi_io_read_async(&context->io, root_ca_file);
            return_try_again(r);
            goto_if_error2(r, "Reading certificate %s", error_cleanup, root_ca_file);

	        fallthrough;

        statecase(context->state, PROVISION_READ_ROOT_CERT);
            r = ifapi_io_read_finish(&context->io, (uint8_t **) &command->root_crt, NULL);
            return_try_again(r);
            goto_if_error(r, "Reading root certificate failed", error_cleanup);

            fallthrough;

        statecase(context->state, PROVISION_EK_CHECK_CERT);
            r = ifapi_verify_ek_cert(command->root_crt, command->intermed_crt, command->pem_cert);
            SAFE_FREE(command->root_crt);
            SAFE_FREE(command->intermed_crt);
            goto_if_error2(r, "Verify EK certificate", error_cleanup);

            fallthrough;

        statecase(context->state, PROVISION_EK_WRITE_PREPARE);
            pkeyObject->objectType = IFAPI_KEY_OBJ;
            pkeyObject->system = command->public_templ.system;
            strdup_check(pkeyObject->misc.key.certificate, command->pem_cert, r, error_cleanup);
            SAFE_FREE(command->pem_cert);

            /* Perform esys serialization if necessary */
            r = ifapi_esys_serialize_object(context->esys,
                    pkeyObject);
            goto_if_error(r, "Prepare serialization", error_cleanup);

            /* Start writing the EK to the key store */
            r = ifapi_keystore_store_async(&context->keystore, &context->io, "HE/EK",
                    pkeyObject);
            goto_if_error_reset_state(r, "Could not open: %sh", error_cleanup, "HE/EK");

            fallthrough;

        statecase(context->state, PROVISION_EK_WRITE);
            /* Finish writing the EK to the key store */
            r = ifapi_keystore_store_finish(&context->keystore, &context->io);
            return_try_again(r);
            goto_if_error_reset_state(r, "write_finish failed", error_cleanup);

            /* Clean objects used for EK computation */
            ifapi_cleanup_ifapi_object(pkeyObject);
            memset(&command->public_templ, 0, sizeof(IFAPI_KEY_TEMPLATE));
            SAFE_FREE(hierarchy->misc.hierarchy.description);
            ifapi_init_hierarchy_object(hierarchy, ESYS_TR_RH_LOCKOUT);
            strdup_check(hierarchy->misc.hierarchy.description, "Lockout Hierarchy",
                    r, error_cleanup);

            if (!command->authValueLockout ||
                strcmp(command->authValueLockout, "") == 0) {
                context->state = PROVISION_LOCKOUT_CHANGE_POLICY;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }

            if (strlen(command->authValueLockout) > sizeof(TPMU_HA)) {
                goto_error(r, TSS2_FAPI_RC_BAD_VALUE,
                        "Password too long.", error_cleanup);
            }
            memcpy(&command->hierarchy_auth.buffer[0],
                   command->authValueLockout, strlen(command->authValueLockout));
            command->hierarchy_auth.size = strlen(command->authValueLockout);
            context->state = PROVISION_CHANGE_LOCKOUT_AUTH;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, PROVISION_WAIT_FOR_SRK_PERSISTENT);
            r = Esys_EvictControl_Finish(context->esys, &pkeyObject->handle);
            return_try_again(r);
            goto_if_error(r, "Evict control failed", error_cleanup);

            context->state = PROVISION_SRK_WRITE_PREPARE;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, PROVISION_WAIT_FOR_EK_PERSISTENT);
            r = Esys_EvictControl_Finish(context->esys, &pkeyObject->handle);
            return_try_again(r);
            goto_if_error(r, "Evict control failed", error_cleanup);

            context->state = PROVISION_INIT_GET_CAP2;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecase(context->state, PROVISION_CHANGE_LOCKOUT_AUTH);
            r = ifapi_change_auth_hierarchy(context, ESYS_TR_RH_LOCKOUT,
                    &command->hierarchy, &command->hierarchy_auth);
            return_try_again(r);
            goto_if_error(r, "Change auth hierarchy.", error_cleanup);

            context->state = PROVISION_LOCKOUT_CHANGE_POLICY;
            fallthrough;

        statecase(context->state, PROVISION_LOCKOUT_CHANGE_POLICY);
            r = ifapi_change_policy_hierarchy(context, ESYS_TR_RH_OWNER,
                    hierarchy, defaultProfile->sh_policy);
            return_try_again(r);
            goto_if_error(r, "Change policy LOCKOUT", error_cleanup);

            /* Start writing the lockout hierarchy object to the key store */
            r = ifapi_keystore_store_async(&context->keystore, &context->io, "/LOCKOUT",
                    &command->hierarchy);
            goto_if_error_reset_state(r, "Could not open: %sh",
                    error_cleanup, "/LOCKOUT");

            context->state = PROVISION_WRITE_LOCKOUT;
            fallthrough;

        statecase(context->state, PROVISION_WRITE_LOCKOUT);
            /* Finish writing the lockout hierarchy to the key store */
            r = ifapi_keystore_store_finish(&context->keystore, &context->io);
            return_try_again(r);
            goto_if_error_reset_state(r, "write_finish failed", error_cleanup);

            SAFE_FREE(hierarchy->misc.hierarchy.description);
            ifapi_init_hierarchy_object(hierarchy, ESYS_TR_RH_ENDORSEMENT);
            strdup_check(hierarchy->misc.hierarchy.description,
                    "Endorsement Hierarchy", r, error_cleanup);

            context->state = PROVISION_CHANGE_EH_CHECK;
            fallthrough;

        statecase(context->state, PROVISION_CHANGE_EH_CHECK);
            if (command->authValueEh) {
                context->state = PROVISION_CHANGE_EH_AUTH;
                memcpy(&command->hierarchy_auth.buffer[0], command->authValueEh,
                       strlen(command->authValueEh));
                command->hierarchy_auth.size = strlen(command->authValueEh);
            } else {
                context->state = PROVISION_EH_CHANGE_POLICY;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            context->state = PROVISION_CHANGE_EH_AUTH;
            fallthrough;

        statecase(context->state, PROVISION_CHANGE_EH_AUTH);
            r = ifapi_change_auth_hierarchy(context, ESYS_TR_RH_ENDORSEMENT,
                    &command->hierarchy, &command->hierarchy_auth);
            return_try_again(r);
            goto_if_error(r, "Change auth hierarchy.", error_cleanup);

            context->state = PROVISION_EH_CHANGE_POLICY;
            fallthrough;

        statecase(context->state, PROVISION_EH_CHANGE_POLICY);
            r = ifapi_change_policy_hierarchy(context, ESYS_TR_RH_ENDORSEMENT,
                    hierarchy, defaultProfile->eh_policy);
            return_try_again(r);
            goto_if_error(r, "Change policy EH", error_cleanup);

            /* Start writing the endorsement hierarchy object to the key store */
            r = ifapi_keystore_store_async(&context->keystore, &context->io, "/HE",
                    &command->hierarchy);
            goto_if_error_reset_state(r, "Could not open: %sh", error_cleanup, "/HE");

            context->state = PROVISION_WRITE_EH;
            fallthrough;

        statecase(context->state, PROVISION_WRITE_EH);
            /* Finish writing the endorsement hierarchy to the key store */
            r = ifapi_keystore_store_finish(&context->keystore, &context->io);
            return_try_again(r);
            return_if_error_reset_state(r, "write_finish failed");

            SAFE_FREE(hierarchy->misc.hierarchy.description);
            ifapi_init_hierarchy_object(hierarchy, ESYS_TR_RH_OWNER);
            strdup_check(hierarchy->misc.hierarchy.description,
                   "Owner Hierarchy", r, error_cleanup);

            context->state = PROVISION_CHANGE_SH_CHECK;
            fallthrough;

        statecase(context->state, PROVISION_CHANGE_SH_CHECK);
            if (command->authValueSh) {
                context->state = PROVISION_CHANGE_SH_AUTH;
                memcpy(&command->hierarchy_auth.buffer[0], command->authValueSh,
                       strlen(command->authValueSh));
                command->hierarchy_auth.size = strlen(command->authValueSh);
                    context->state = PROVISION_CHANGE_SH_AUTH;
            } else {
                context->state = PROVISION_SH_CHANGE_POLICY;
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
            context->state = PROVISION_CHANGE_SH_AUTH;
            fallthrough;

        statecase(context->state, PROVISION_CHANGE_SH_AUTH);
            r = ifapi_change_auth_hierarchy(context, ESYS_TR_RH_OWNER,
                    &command->hierarchy, &command->hierarchy_auth);
            return_try_again(r);
            goto_if_error(r, "Change auth hierarchy.", error_cleanup);

            context->state = PROVISION_SH_CHANGE_POLICY;
            fallthrough;

        statecase(context->state, PROVISION_SH_CHANGE_POLICY);
            r = ifapi_change_policy_hierarchy(context, ESYS_TR_RH_OWNER,
                    hierarchy, defaultProfile->sh_policy);
            return_try_again(r);
            goto_if_error(r, "Change policy SH", error_cleanup);

            /* Start writing the owner hierarchy object to the key store */
            r = ifapi_keystore_store_async(&context->keystore, &context->io, "/HS",
                    &command->hierarchy);
            goto_if_error_reset_state(r, "Could not open: %sh", error_cleanup, "/HS");
            context->state = PROVISION_WRITE_SH;
            fallthrough;

        statecase(context->state, PROVISION_WRITE_SH);
            r = ifapi_keystore_store_finish(&context->keystore, &context->io);
            return_try_again(r);
            goto_if_error_reset_state(r, "write_finish failed", error_cleanup);
            fallthrough;

        statecase(context->state, PROVISION_FINISHED);
            if (!context->srk_persistent && context->srk_handle != ESYS_TR_NONE) {
                r = Esys_FlushContext_Async(context->esys, context->srk_handle);
                goto_if_error(r, "Flush SRK", error_cleanup);
            }
            fallthrough;

        /* Flush the SRK if not persistent */
        statecase(context->state, PROVISION_FLUSH_SRK);
            if (!context->srk_persistent && context->srk_handle != ESYS_TR_NONE) {
                r = Esys_FlushContext_Finish(context->esys);
                try_again_or_error_goto(r, "Flush SRK", error_cleanup);

                context->srk_handle = ESYS_TR_NONE;

            }
            if (!context->ek_persistent && context->ek_handle != ESYS_TR_NONE) {
                r = Esys_FlushContext_Async(context->esys, context->ek_handle);
                goto_if_error(r, "Flush EK", error_cleanup);
            }
            fallthrough;

         /* Flush the SRK if not persistent */
        statecase(context->state, PROVISION_FLUSH_EK);
            if (!context->ek_persistent && context->ek_handle != ESYS_TR_NONE) {
                r = Esys_FlushContext_Finish(context->esys);
                try_again_or_error_goto(r, "Flush EK", error_cleanup);

                context->ek_handle = ESYS_TR_NONE;
            }

            context->state = _FAPI_STATE_INIT;
            break;

        statecase(context->state, PROVISION_CHECK_FOR_VENDOR_CERT);
            r = Esys_GetCapability_Async(context->esys,
                                         ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                         TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, 1);
            goto_if_error(r, "Esys_GetCapability_Async", error_cleanup);

            fallthrough;

        statecase(context->state, PROVISION_GET_VENDOR);
            r = Esys_GetCapability_Finish(context->esys, &moreData, capabilityData);
            return_try_again(r);
            goto_if_error_reset_state(r, "GetCapablity_Finish", error_cleanup);

            if ((*capabilityData)->data.tpmProperties.tpmProperty[0].value == VENDOR_INTC) {
                /* Get INTEL certificate for EK public hash via web */
                uint8_t *cert_buffer = NULL;
                size_t cert_size;
                TPM2B_PUBLIC public;
                r = ifapi_get_intl_ek_certificate(&pkey->public, &cert_buffer,
                                                  &cert_size);
                goto_if_error_reset_state(r, "Get certificates", error_cleanup);

                r = ifapi_cert_to_pem(cert_buffer, cert_size, &command->pem_cert,
                                      NULL, &public);
                SAFE_FREE(cert_buffer);
                goto_if_error_reset_state(r, "Convert certificate buffer to PEM.",
                                          error_cleanup);
            }
            SAFE_FREE(*capabilityData);
            context->state = PROVISION_EK_WRITE_PREPARE;
            return TSS2_FAPI_RC_TRY_AGAIN;

        statecasedefault(context->state);
    }

error_cleanup:
    /* Primaries might not have been flushed in error cases */
    ifapi_primary_clean(context);
    SAFE_FREE(command->root_crt);
    SAFE_FREE(*capabilityData);
    SAFE_FREE(hierarchy->misc.hierarchy.description);
    SAFE_FREE(command->authValueLockout);
    SAFE_FREE(command->authValueEh);
    SAFE_FREE(command->authValueSh);
    SAFE_FREE(command->pem_cert);
    SAFE_FREE(certData);
    SAFE_FREE(nvPublic);
    LOG_TRACE("finished");
    return r;
}
