/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "tss2_mu.h"
#include "tss2_sys.h"
#include "tss2_esys.h"

#include "esys_types.h"
#include "esys_iutil.h"
#include "esys_mu.h"
#define LOGMODULE esys
#include "util/log.h"

/** Store command parameters inside the ESYS_CONTEXT for use during _Finish */
static void store_input_parameters (
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    UINT16 size,
    UINT16 offset)
{
    esysContext->in.NV_Certify.signHandle = signHandle;
    esysContext->in.NV_Certify.authHandle = authHandle;
    esysContext->in.NV_Certify.nvIndex = nvIndex;
    esysContext->in.NV_Certify.size = size;
    esysContext->in.NV_Certify.offset = offset;
    if (qualifyingData == NULL) {
        esysContext->in.NV_Certify.qualifyingData = NULL;
    } else {
        esysContext->in.NV_Certify.qualifyingDataData = *qualifyingData;
        esysContext->in.NV_Certify.qualifyingData =
            &esysContext->in.NV_Certify.qualifyingDataData;
    }
    if (inScheme == NULL) {
        esysContext->in.NV_Certify.inScheme = NULL;
    } else {
        esysContext->in.NV_Certify.inSchemeData = *inScheme;
        esysContext->in.NV_Certify.inScheme =
            &esysContext->in.NV_Certify.inSchemeData;
    }
}

/** One-Call function for TPM2_NV_Certify
 *
 * This function invokes the TPM2_NV_Certify command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in]  signHandle Handle of the key used to sign the attestation structure.
 * @param[in]  authHandle Handle indicating the source of the authorization value
 *             for the NV Index.
 * @param[in]  nvIndex Index for the area to be certified.
 * @param[in]  shandle1 Session handle for authorization of signHandle
 * @param[in]  shandle2 Session handle for authorization of authHandle
 * @param[in]  shandle3 Third session handle.
 * @param[in]  qualifyingData User-provided qualifying data.
 * @param[in]  inScheme TPM2_Signing scheme to use if the scheme for signHandle is
 *             TPM2_ALG_NULL.
 * @param[in]  size Number of octets to certify.
 * @param[in]  offset Octet offset into the area.
 * @param[out] certifyInfo The structure that was signed.
 *             (callee-allocated)
 * @param[out] signature The asymmetric signature over certifyInfo using the key
 *             referenced by signHandle.
 *             (callee-allocated)
 * @retval TSS2_RC_SUCCESS on success
 * @retval ESYS_RC_SUCCESS if the function call was a success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if the esysContext or required input
 *         pointers or required output handle references are NULL.
 * @retval TSS2_ESYS_RC_BAD_CONTEXT: if esysContext corruption is detected.
 * @retval TSS2_ESYS_RC_MEMORY: if the ESAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_ESYS_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_RESPONSE: if the TPM's response does not
 *          at least contain the tag, response length, and response code.
 * @retval TSS2_ESYS_RC_MALFORMED_RESPONSE: if the TPM's response is corrupted.
 * @retval TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS: if more than one session has
 *         the 'decrypt' attribute bit set.
 * @retval TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS: if more than one session has
 *         the 'encrypt' attribute bit set.
 * @retval TSS2_ESYS_RC_BAD_TR: if any of the ESYS_TR objects are unknown to the
 *         ESYS_CONTEXT or are of the wrong type or if required ESYS_TR objects
 *         are ESYS_TR_NONE.
 * @retval TSS2_RCs produced by lower layers of the software stack may be
 *         returned to the caller unaltered unless handled internally.
 */
TSS2_RC
Esys_NV_Certify(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    UINT16 size,
    UINT16 offset,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature)
{
    TSS2_RC r;

    r = Esys_NV_Certify_Async(esysContext,
                signHandle,
                authHandle,
                nvIndex,
                shandle1,
                shandle2,
                shandle3,
                qualifyingData,
                inScheme,
                size,
                offset);
    return_if_error(r, "Error in async function");

    /* Set the timeout to indefinite for now, since we want _Finish to block */
    int32_t timeouttmp = esysContext->timeout;
    esysContext->timeout = -1;
    /*
     * Now we call the finish function, until return code is not equal to
     * from TSS2_BASE_RC_TRY_AGAIN.
     * Note that the finish function may return TSS2_RC_TRY_AGAIN, even if we
     * have set the timeout to -1. This occurs for example if the TPM requests
     * a retransmission of the command via TPM2_RC_YIELDED.
     */
    do {
        r = Esys_NV_Certify_Finish(esysContext,
                certifyInfo,
                signature);
        /* This is just debug information about the reattempt to finish the
           command */
        if ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN)
            LOG_DEBUG("A layer below returned TRY_AGAIN: %" PRIx32
                      " => resubmitting command", r);
    } while ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN);

    /* Restore the timeout value to the original value */
    esysContext->timeout = timeouttmp;
    return_if_error(r, "Esys Finish");

    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for TPM2_NV_Certify
 *
 * This function invokes the TPM2_NV_Certify command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_NV_Certify_Finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in]  signHandle Handle of the key used to sign the attestation structure.
 * @param[in]  authHandle Handle indicating the source of the authorization value
 *             for the NV Index.
 * @param[in]  nvIndex Index for the area to be certified.
 * @param[in]  shandle1 Session handle for authorization of signHandle
 * @param[in]  shandle2 Session handle for authorization of authHandle
 * @param[in]  shandle3 Third session handle.
 * @param[in]  qualifyingData User-provided qualifying data.
 * @param[in]  inScheme TPM2_Signing scheme to use if the scheme for signHandle is
 *             TPM2_ALG_NULL.
 * @param[in]  size Number of octets to certify.
 * @param[in]  offset Octet offset into the area.
 * @retval ESYS_RC_SUCCESS if the function call was a success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if the esysContext or required input
 *         pointers or required output handle references are NULL.
 * @retval TSS2_ESYS_RC_BAD_CONTEXT: if esysContext corruption is detected.
 * @retval TSS2_ESYS_RC_MEMORY: if the ESAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_RCs produced by lower layers of the software stack may be
           returned to the caller unaltered unless handled internally.
 * @retval TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS: if more than one session has
 *         the 'decrypt' attribute bit set.
 * @retval TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS: if more than one session has
 *         the 'encrypt' attribute bit set.
 * @retval TSS2_ESYS_RC_BAD_TR: if any of the ESYS_TR objects are unknown to the
           ESYS_CONTEXT or are of the wrong type or if required ESYS_TR objects
           are ESYS_TR_NONE.
 */
TSS2_RC
Esys_NV_Certify_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    UINT16 size,
    UINT16 offset)
{
    TSS2_RC r;
    LOG_TRACE("context=%p, signHandle=%"PRIx32 ", authHandle=%"PRIx32 ","
              "nvIndex=%"PRIx32 ", qualifyingData=%p, inScheme=%p,"
              "size=%04"PRIx16", offset=%04"PRIx16"",
              esysContext, signHandle, authHandle, nvIndex, qualifyingData,
              inScheme, size, offset);
    TSS2L_SYS_AUTH_COMMAND auths;
    RSRC_NODE_T *signHandleNode;
    RSRC_NODE_T *authHandleNode;
    RSRC_NODE_T *nvIndexNode;

    /* Check context, sequence correctness and set state to error for now */
    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;
    esysContext->state = _ESYS_STATE_INTERNALERROR;

    /* Check and store input parameters */
    r = check_session_feasibility(shandle1, shandle2, shandle3, 1);
    return_state_if_error(r, _ESYS_STATE_INIT, "Check session usage");
    store_input_parameters(esysContext, signHandle, authHandle, nvIndex,
                qualifyingData,
                inScheme,
                size,
                offset);

    /* Retrieve the metadata objects for provided handles */
    r = esys_GetResourceObject(esysContext, signHandle, &signHandleNode);
    return_state_if_error(r, _ESYS_STATE_INIT, "signHandle unknown.");
    r = esys_GetResourceObject(esysContext, authHandle, &authHandleNode);
    return_state_if_error(r, _ESYS_STATE_INIT, "authHandle unknown.");
    r = esys_GetResourceObject(esysContext, nvIndex, &nvIndexNode);
    return_state_if_error(r, _ESYS_STATE_INIT, "nvIndex unknown.");

    /* Initial invocation of SAPI to prepare the command buffer with parameters */
    r = Tss2_Sys_NV_Certify_Prepare(esysContext->sys,
                (signHandleNode == NULL) ? TPM2_RH_NULL : signHandleNode->rsrc.handle,
                (authHandleNode == NULL) ? TPM2_RH_NULL : authHandleNode->rsrc.handle,
                (nvIndexNode == NULL) ? TPM2_RH_NULL : nvIndexNode->rsrc.handle,
                qualifyingData,
                inScheme,
                size,
                offset);
    return_state_if_error(r, _ESYS_STATE_INIT, "SAPI Prepare returned error.");

    /* Calculate the cpHash Values */
    r = init_session_tab(esysContext, shandle1, shandle2, shandle3);
    return_state_if_error(r, _ESYS_STATE_INIT, "Initialize session resources");
    iesys_compute_session_value(esysContext->session_tab[0],
                &signHandleNode->rsrc.name, &signHandleNode->auth);
    iesys_compute_session_value(esysContext->session_tab[1],
                &authHandleNode->rsrc.name, &authHandleNode->auth);
    iesys_compute_session_value(esysContext->session_tab[2], NULL, NULL);

    /* Generate the auth values and set them in the SAPI command buffer */
    r = iesys_gen_auths(esysContext, signHandleNode, authHandleNode, nvIndexNode, &auths);
    return_state_if_error(r, _ESYS_STATE_INIT, "Error in computation of auth values");
    esysContext->authsCount = auths.count;
    r = Tss2_Sys_SetCmdAuths(esysContext->sys, &auths);
    return_state_if_error(r, _ESYS_STATE_INIT, "SAPI error on SetCmdAuths");

    /* Trigger execution and finish the async invocation */
    r = Tss2_Sys_ExecuteAsync(esysContext->sys);
    return_state_if_error(r, _ESYS_STATE_INTERNALERROR, "Finish (Execute Async)");

    esysContext->state = _ESYS_STATE_SENT;

    return r;
}

/** Asynchronous finish function for TPM2_NV_Certify
 *
 * This function returns the results of a TPM2_NV_Certify command
 * invoked via Esys_NV_Certify_Finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[out] certifyInfo The structure that was signed.
 *             (callee-allocated)
 * @param[out] signature The asymmetric signature over certifyInfo using the key
 *             referenced by signHandle.
 *             (callee-allocated)
 * @retval TSS2_RC_SUCCESS on success
 * @retval ESYS_RC_SUCCESS if the function call was a success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if the esysContext or required input
 *         pointers or required output handle references are NULL.
 * @retval TSS2_ESYS_RC_BAD_CONTEXT: if esysContext corruption is detected.
 * @retval TSS2_ESYS_RC_MEMORY: if the ESAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_ESYS_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_ESYS_RC_TRY_AGAIN: if the timeout counter expires before the
 *         TPM response is received.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_RESPONSE: if the TPM's response does not
 *          at least contain the tag, response length, and response code.
 * @retval TSS2_ESYS_RC_MALFORMED_RESPONSE: if the TPM's response is corrupted.
 * @retval TSS2_RCs produced by lower layers of the software stack may be
 *         returned to the caller unaltered unless handled internally.
 */
TSS2_RC
Esys_NV_Certify_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature)
{
    TSS2_RC r;
    LOG_TRACE("context=%p, certifyInfo=%p, signature=%p",
              esysContext, certifyInfo, signature);

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    /* Check for correct sequence and set sequence to irregular for now */
    if (esysContext->state != _ESYS_STATE_SENT) {
        LOG_ERROR("Esys called in bad sequence.");
        return TSS2_ESYS_RC_BAD_SEQUENCE;
    }
    esysContext->state = _ESYS_STATE_INTERNALERROR;

    /* Allocate memory for response parameters */
    if (certifyInfo != NULL) {
        *certifyInfo = calloc(sizeof(TPM2B_ATTEST), 1);
        if (*certifyInfo == NULL) {
            return_error(TSS2_ESYS_RC_MEMORY, "Out of memory");
        }
    }
    if (signature != NULL) {
        *signature = calloc(sizeof(TPMT_SIGNATURE), 1);
        if (*signature == NULL) {
            goto_error(r, TSS2_ESYS_RC_MEMORY, "Out of memory", error_cleanup);
        }
    }

    /*Receive the TPM response and handle resubmissions if necessary. */
    r = Tss2_Sys_ExecuteFinish(esysContext->sys, esysContext->timeout);
    if ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN) {
        LOG_DEBUG("A layer below returned TRY_AGAIN: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_SENT;
        goto error_cleanup;
    }
    /* This block handle the resubmission of TPM commands given a certain set of
     * TPM response codes. */
    if (r == TPM2_RC_RETRY || r == TPM2_RC_TESTING || r == TPM2_RC_YIELDED) {
        LOG_DEBUG("TPM returned RETRY, TESTING or YIELDED, which triggers a "
            "resubmission: %" PRIx32, r);
        if (esysContext->submissionCount >= _ESYS_MAX_SUBMISSIONS) {
            LOG_WARNING("Maximum number of (re)submissions has been reached.");
            esysContext->state = _ESYS_STATE_INIT;
            goto error_cleanup;
        }
        esysContext->state = _ESYS_STATE_RESUBMISSION;
        r = Esys_NV_Certify_Async(esysContext,
                esysContext->in.NV_Certify.signHandle,
                esysContext->in.NV_Certify.authHandle,
                esysContext->in.NV_Certify.nvIndex,
                esysContext->session_type[0],
                esysContext->session_type[1],
                esysContext->session_type[2],
                esysContext->in.NV_Certify.qualifyingData,
                esysContext->in.NV_Certify.inScheme,
                esysContext->in.NV_Certify.size,
                esysContext->in.NV_Certify.offset);
        if (r != TSS2_RC_SUCCESS) {
            LOG_WARNING("Error attempting to resubmit");
            /* We do not set esysContext->state here but inherit the most recent
             * state of the _async function. */
            goto error_cleanup;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        LOG_DEBUG("Resubmission initiated and returning RC_TRY_AGAIN.");
        goto error_cleanup;
    }
    /* The following is the "regular error" handling. */
    if (r != TSS2_RC_SUCCESS && (r & TSS2_RC_LAYER_MASK) == 0) {
        LOG_WARNING("Received TPM Error");
        esysContext->state = _ESYS_STATE_INIT;
        goto error_cleanup;
    } else if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Received a non-TPM Error");
        esysContext->state = _ESYS_STATE_INTERNALERROR;
        goto error_cleanup;
    }

    /*
     * Now the verification of the response (hmac check) and if necessary the
     * parameter decryption have to be done.
     */
    r = iesys_check_response(esysContext);
    goto_state_if_error(r, _ESYS_STATE_INTERNALERROR, "Error: check response",
                      error_cleanup);
    /*
     * After the verification of the response we call the complete function
     * to deliver the result.
     */
    r = Tss2_Sys_NV_Certify_Complete(esysContext->sys,
                (certifyInfo != NULL) ? *certifyInfo : NULL,
                (signature != NULL) ? *signature : NULL);
    goto_state_if_error(r, _ESYS_STATE_INTERNALERROR, "Received error from SAPI"
                        " unmarshaling" ,error_cleanup);
    esysContext->state = _ESYS_STATE_INIT;

    return TSS2_RC_SUCCESS;

error_cleanup:
    if (certifyInfo != NULL)
        SAFE_FREE(*certifyInfo);
    if (signature != NULL)
        SAFE_FREE(*signature);

    return r;
}
