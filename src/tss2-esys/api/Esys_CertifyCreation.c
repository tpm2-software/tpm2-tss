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

/** Store command parameters inside the ESYS_CONTEXT for use during _finish */
static void store_input_parameters (
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR objectHandle,
    const TPM2B_DATA *qualifyingData,
    const TPM2B_DIGEST *creationHash,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_CREATION *creationTicket)
{
    esysContext->in.CertifyCreation.signHandle = signHandle;
    esysContext->in.CertifyCreation.objectHandle = objectHandle;
    if (qualifyingData == NULL) {
        esysContext->in.CertifyCreation.qualifyingData = NULL;
    } else {
        esysContext->in.CertifyCreation.qualifyingDataData = *qualifyingData;
        esysContext->in.CertifyCreation.qualifyingData =
            &esysContext->in.CertifyCreation.qualifyingDataData;
    }
    if (creationHash == NULL) {
        esysContext->in.CertifyCreation.creationHash = NULL;
    } else {
        esysContext->in.CertifyCreation.creationHashData = *creationHash;
        esysContext->in.CertifyCreation.creationHash =
            &esysContext->in.CertifyCreation.creationHashData;
    }
    if (inScheme == NULL) {
        esysContext->in.CertifyCreation.inScheme = NULL;
    } else {
        esysContext->in.CertifyCreation.inSchemeData = *inScheme;
        esysContext->in.CertifyCreation.inScheme =
            &esysContext->in.CertifyCreation.inSchemeData;
    }
    if (creationTicket == NULL) {
        esysContext->in.CertifyCreation.creationTicket = NULL;
    } else {
        esysContext->in.CertifyCreation.creationTicketData = *creationTicket;
        esysContext->in.CertifyCreation.creationTicket =
            &esysContext->in.CertifyCreation.creationTicketData;
    }
}

/** One-Call function for TPM2_CertifyCreation
 *
 * This function invokes the TPM2_CertifyCreation command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] signHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] objectHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] qualifyingData Input parameter of type TPM2B_DATA.
 * @param[in] creationHash Input parameter of type TPM2B_DIGEST.
 * @param[in] inScheme Input parameter of type TPMT_SIG_SCHEME.
 * @param[in] creationTicket Input parameter of type TPMT_TK_CREATION.
 * @param[out] certifyInfo (callee-allocated) Output parameter
 *    of type TPM2B_ATTEST. May be NULL if this value is not required.
 * @param[out] signature (callee-allocated) Output parameter
 *    of type TPMT_SIGNATURE. May be NULL if this value is not required.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_CertifyCreation(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPM2B_DIGEST *creationHash,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_CREATION *creationTicket,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature)
{
    TSS2_RC r;

    r = Esys_CertifyCreation_async(esysContext,
                signHandle,
                objectHandle,
                shandle1,
                shandle2,
                shandle3,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket);
    return_if_error(r, "Error in async function");

    /* Set the timeout to indefinite for now, since we want _finish to block */
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
        r = Esys_CertifyCreation_finish(esysContext,
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

/** Asynchronous function for TPM2_CertifyCreation
 *
 * This function invokes the TPM2_CertifyCreation command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_CertifyCreation_finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] signHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] objectHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] qualifyingData Input parameter of type TPM2B_DATA.
 * @param[in] creationHash Input parameter of type TPM2B_DIGEST.
 * @param[in] inScheme Input parameter of type TPMT_SIG_SCHEME.
 * @param[in] creationTicket Input parameter of type TPMT_TK_CREATION.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_CertifyCreation_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPM2B_DIGEST *creationHash,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_CREATION *creationTicket)
{
    TSS2_RC r;
    TSS2L_SYS_AUTH_COMMAND auths;
    RSRC_NODE_T *signHandleNode;
    RSRC_NODE_T *objectHandleNode;

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;
    r = check_session_feasability(shandle1, shandle2, shandle3, 1);
    return_if_error(r, "Check session usage");

    store_input_parameters(esysContext, signHandle, objectHandle,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket);
    r = esys_GetResourceObject(esysContext, signHandle, &signHandleNode);
    if (r != TPM2_RC_SUCCESS)
        return r;
    r = esys_GetResourceObject(esysContext, objectHandle, &objectHandleNode);
    if (r != TPM2_RC_SUCCESS)
        return r;
    r = Tss2_Sys_CertifyCreation_Prepare(esysContext->sys,
                (signHandleNode == NULL) ? TPM2_RH_NULL : signHandleNode->rsrc.handle,
                (objectHandleNode == NULL) ? TPM2_RH_NULL : objectHandleNode->rsrc.handle,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error async CertifyCreation");
        return r;
    }
    r = init_session_tab(esysContext, shandle1, shandle2, shandle3);
    return_if_error(r, "Initialize session resources");

    iesys_compute_session_value(esysContext->session_tab[0],
                &signHandleNode->rsrc.name, &signHandleNode->auth);
    iesys_compute_session_value(esysContext->session_tab[1], NULL, NULL);
    iesys_compute_session_value(esysContext->session_tab[2], NULL, NULL);
    r = iesys_gen_auths(esysContext, signHandleNode, objectHandleNode, NULL, &auths);
    return_if_error(r, "Error in computation of auth values");

    esysContext->authsCount = auths.count;
    r = Tss2_Sys_SetCmdAuths(esysContext->sys, &auths);
    if (r != TSS2_RC_SUCCESS) {
        return r;
    }

    r = Tss2_Sys_ExecuteAsync(esysContext->sys);
    return_if_error(r, "Finish (Execute Async)");

    esysContext->state = _ESYS_STATE_SENT;

    return r;
}

/** Asynchronous finish function for TPM2_CertifyCreation
 *
 * This function returns the results of a TPM2_CertifyCreation command
 * invoked via Esys_CertifyCreation_finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[out] certifyInfo (callee-allocated) Output parameter
 *    of type TPM2B_ATTEST. May be NULL if this value is not required.
 * @param[out] signature (callee-allocated) Output parameter
 *    of type TPMT_SIGNATURE. May be NULL if this value is not required.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function.
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_CertifyCreation_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature)
{
    LOG_TRACE("complete");
    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    if (esysContext->state != _ESYS_STATE_SENT) {
        LOG_ERROR("Esys called in bad sequence.");
        return TSS2_ESYS_RC_BAD_SEQUENCE;
    }
    TSS2_RC r;
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
    r = Tss2_Sys_ExecuteFinish(esysContext->sys, esysContext->timeout);
    if ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN) {
        LOG_DEBUG("A layer below returned TRY_AGAIN: %" PRIx32, r);
        goto error_cleanup;
    }
    if (r == TPM2_RC_RETRY || r == TPM2_RC_TESTING || r == TPM2_RC_YIELDED) {
        LOG_DEBUG("TPM returned RETRY, TESTING or YIELDED, which triggers a "
            "resubmission: %" PRIx32, r);
        if (esysContext->submissionCount >= _ESYS_MAX_SUBMISSIONS) {
            LOG_WARNING("Maximum number of resubmissions has been reached.");
            esysContext->state = _ESYS_STATE_ERRORRESPONSE;
            goto error_cleanup;
        }
        esysContext->state = _ESYS_STATE_RESUBMISSION;
        r = Esys_CertifyCreation_async(esysContext,
                esysContext->in.CertifyCreation.signHandle,
                esysContext->in.CertifyCreation.objectHandle,
                esysContext->session_type[0],
                esysContext->session_type[1],
                esysContext->session_type[2],
                esysContext->in.CertifyCreation.qualifyingData,
                esysContext->in.CertifyCreation.creationHash,
                esysContext->in.CertifyCreation.inScheme,
                esysContext->in.CertifyCreation.creationTicket);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Error attempting to resubmit");
            goto error_cleanup;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        goto error_cleanup;
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) CertifyCreation");
        goto error_cleanup;
    }
    /*
     * Now the verification of the response (hmac check) and if necessary the
     * parameter decryption have to be done
     */
    r = iesys_check_response(esysContext);
    goto_if_error(r, "Error: check response",
                      error_cleanup);
    /*
     * After the verification of the response we call the complete function
     * to deliver the result.
     */
    r = Tss2_Sys_CertifyCreation_Complete(esysContext->sys,
                (certifyInfo != NULL) ? *certifyInfo : NULL,
                (signature != NULL) ? *signature : NULL);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) CertifyCreation: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_ERRORRESPONSE;
        goto error_cleanup;;
    }
    esysContext->state = _ESYS_STATE_FINISHED;

    return r;

error_cleanup:
    if (certifyInfo != NULL)
        SAFE_FREE(*certifyInfo);
    if (signature != NULL)
        SAFE_FREE(*signature);
    return r;
}
