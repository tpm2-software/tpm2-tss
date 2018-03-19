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
#ifndef TSS2_API_VERSION_1_2_1_108
#error Version missmatch among TSS2 header files !
#endif /* TSS2_API_VERSION_1_2_1_108 */
#include "esys_types.h"
#include "tss2_esys.h"
#include "esys_iutil.h"
#include "esys_mu.h"
#include "tss2_sys.h"
#define LOGMODULE esys
#include "util/log.h"

/** Store command parameters inside the ESYS_CONTEXT for use during _finish */
static void store_input_parameters (
    ESYS_CONTEXT *esysContext,
    ESYS_TR primaryHandle,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR)
{
    esysContext->in.CreatePrimary.primaryHandle = primaryHandle;
    if (inSensitive == NULL) {
        esysContext->in.CreatePrimary.inSensitive = NULL;
    } else {
        esysContext->in.CreatePrimary.inSensitiveData = *inSensitive;
        esysContext->in.CreatePrimary.inSensitive =
            &esysContext->in.CreatePrimary.inSensitiveData;
    }
    if (inPublic == NULL) {
        esysContext->in.CreatePrimary.inPublic = NULL;
    } else {
        esysContext->in.CreatePrimary.inPublicData = *inPublic;
        esysContext->in.CreatePrimary.inPublic =
            &esysContext->in.CreatePrimary.inPublicData;
    }
    if (outsideInfo == NULL) {
        esysContext->in.CreatePrimary.outsideInfo = NULL;
    } else {
        esysContext->in.CreatePrimary.outsideInfoData = *outsideInfo;
        esysContext->in.CreatePrimary.outsideInfo =
            &esysContext->in.CreatePrimary.outsideInfoData;
    }
    if (creationPCR == NULL) {
        esysContext->in.CreatePrimary.creationPCR = NULL;
    } else {
        esysContext->in.CreatePrimary.creationPCRData = *creationPCR;
        esysContext->in.CreatePrimary.creationPCR =
            &esysContext->in.CreatePrimary.creationPCRData;
    }
}

/** One-Call function for TPM2_CreatePrimary
 *
 * This function invokes the TPM2_CreatePrimary command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] primaryHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_RH_HIERARCHY.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] inSensitive Input parameter of type TPM2B_SENSITIVE_CREATE.
 * @param[in] inPublic Input parameter of type TPM2B_PUBLIC.
 * @param[in] outsideInfo Input parameter of type TPM2B_DATA.
 * @param[in] creationPCR Input parameter of type TPML_PCR_SELECTION.
 * @param[out] outPublic (callee-allocated) Output parameter
 *    of type TPM2B_PUBLIC. May be NULL if this value is not required.
 * @param[out] creationData (callee-allocated) Output parameter
 *    of type TPM2B_CREATION_DATA. May be NULL if this value is not required.
 * @param[out] creationHash (callee-allocated) Output parameter
 *    of type TPM2B_DIGEST. May be NULL if this value is not required.
 * @param[out] creationTicket (callee-allocated) Output parameter
 *    of type TPMT_TK_CREATION. May be NULL if this value is not required.
 * @param[out] objectHandle  ESYS_TR handle of ESYS resource for TPM2_HANDLE.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_CreatePrimary(
    ESYS_CONTEXT *esysContext,
    ESYS_TR primaryHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR,
    ESYS_TR *objectHandle,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket)
{
    TSS2_RC r;

    r = Esys_CreatePrimary_async(esysContext,
                primaryHandle,
                shandle1,
                shandle2,
                shandle3,
                inSensitive,
                inPublic,
                outsideInfo,
                creationPCR);
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
        r = Esys_CreatePrimary_finish(esysContext,
                objectHandle,
                outPublic,
                creationData,
                creationHash,
                creationTicket);
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

/** Asynchronous function for TPM2_CreatePrimary
 *
 * This function invokes the TPM2_CreatePrimary command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_CreatePrimary_finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] primaryHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_RH_HIERARCHY.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] inSensitive Input parameter of type TPM2B_SENSITIVE_CREATE.
 * @param[in] inPublic Input parameter of type TPM2B_PUBLIC.
 * @param[in] outsideInfo Input parameter of type TPM2B_DATA.
 * @param[in] creationPCR Input parameter of type TPML_PCR_SELECTION.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_CreatePrimary_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR primaryHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR)
{
    TSS2_RC r;
    TSS2L_SYS_AUTH_COMMAND auths = { 0 };
    RSRC_NODE_T *primaryHandleNode;

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;
    r = check_session_feasability(shandle1, shandle2, shandle3, 1);
    return_if_error(r, "Check session usage");

    store_input_parameters(esysContext, primaryHandle,
                inSensitive,
                inPublic,
                outsideInfo,
                creationPCR);
    r = esys_GetResourceObject(esysContext, primaryHandle, &primaryHandleNode);
    if (r != TPM2_RC_SUCCESS)
        return r;
    r = Tss2_Sys_CreatePrimary_Prepare(esysContext->sys,
                (primaryHandleNode == NULL) ? TPM2_RH_NULL : primaryHandleNode->rsrc.handle,
                inSensitive,
                inPublic,
                outsideInfo,
                creationPCR);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error async CreatePrimary");
        return r;
    }
    r = init_session_tab(esysContext, shandle1, shandle2, shandle3);
    return_if_error(r, "Initialize session resources");

    iesys_compute_session_value(esysContext->session_tab[0],
                &primaryHandleNode->rsrc.name, &primaryHandleNode->auth);
    iesys_compute_session_value(esysContext->session_tab[1], NULL, NULL);
    iesys_compute_session_value(esysContext->session_tab[2], NULL, NULL);
    r = iesys_gen_auths(esysContext, primaryHandleNode, NULL, NULL, &auths);
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

/** Asynchronous finish function for TPM2_CreatePrimary
 *
 * This function returns the results of a TPM2_CreatePrimary command
 * invoked via Esys_CreatePrimary_finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[out] outPublic (callee-allocated) Output parameter
 *    of type TPM2B_PUBLIC. May be NULL if this value is not required.
 * @param[out] creationData (callee-allocated) Output parameter
 *    of type TPM2B_CREATION_DATA. May be NULL if this value is not required.
 * @param[out] creationHash (callee-allocated) Output parameter
 *    of type TPM2B_DIGEST. May be NULL if this value is not required.
 * @param[out] creationTicket (callee-allocated) Output parameter
 *    of type TPMT_TK_CREATION. May be NULL if this value is not required.
 * @param[out] objectHandle  ESYS_TR handle of ESYS resource for TPM2_HANDLE.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function.
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_CreatePrimary_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket)
{
    TPM2B_PUBLIC *loutPublic = NULL;
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
    TPM2B_NAME name;
    IESYS_RESOURCE *objectHandleRsrc = NULL;
    RSRC_NODE_T *objectHandleNode = NULL;

    if (objectHandle == NULL) {
        LOG_ERROR("Handle objectHandle may not be NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    *objectHandle = esysContext->esys_handle_cnt++;
    r = esys_CreateResourceObject(esysContext, *objectHandle, &objectHandleNode);
    if (r != TSS2_RC_SUCCESS)
        return r;

    loutPublic = calloc(sizeof(TPM2B_PUBLIC), 1);
    if (loutPublic == NULL) {
        goto_error(r, TSS2_ESYS_RC_MEMORY, "Out of memory", error_cleanup);
    }
    if (creationData != NULL) {
        *creationData = calloc(sizeof(TPM2B_CREATION_DATA), 1);
        if (*creationData == NULL) {
            goto_error(r, TSS2_ESYS_RC_MEMORY, "Out of memory", error_cleanup);
        }
    }
    if (creationHash != NULL) {
        *creationHash = calloc(sizeof(TPM2B_DIGEST), 1);
        if (*creationHash == NULL) {
            goto_error(r, TSS2_ESYS_RC_MEMORY, "Out of memory", error_cleanup);
        }
    }
    if (creationTicket != NULL) {
        *creationTicket = calloc(sizeof(TPMT_TK_CREATION), 1);
        if (*creationTicket == NULL) {
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
        r = Esys_CreatePrimary_async(esysContext,
                esysContext->in.CreatePrimary.primaryHandle,
                esysContext->session_type[0],
                esysContext->session_type[1],
                esysContext->session_type[2],
                esysContext->in.CreatePrimary.inSensitive,
                esysContext->in.CreatePrimary.inPublic,
                esysContext->in.CreatePrimary.outsideInfo,
                esysContext->in.CreatePrimary.creationPCR);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Error attempting to resubmit");
            goto error_cleanup;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        goto error_cleanup;
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) CreatePrimary");
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
    r = Tss2_Sys_CreatePrimary_Complete(esysContext->sys,
                &objectHandleNode->rsrc.handle,
                loutPublic,
                (creationData != NULL) ? *creationData : NULL,
                (creationHash != NULL) ? *creationHash : NULL,
                (creationTicket != NULL) ? *creationTicket : NULL,
                &name);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) CreatePrimary: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_ERRORRESPONSE;
        goto error_cleanup;;
    }

    if (!iesys_compare_name(loutPublic, &name))
        goto_error(r, TSS2_ESYS_RC_MALFORMED_RESPONSE,
            "in Public name not equal name in response", error_cleanup);

    objectHandleNode->rsrc.name = name;
    objectHandleNode->rsrc.rsrcType = IESYSC_KEY_RSRC;
    objectHandleNode->rsrc.misc.rsrc_key_pub = *loutPublic;
    if (outPublic != NULL)
        *outPublic = loutPublic;
    else
        SAFE_FREE(loutPublic);

    esysContext->state = _ESYS_STATE_FINISHED;

    return r;

error_cleanup:
    Esys_TR_Close(esysContext, objectHandle);
    SAFE_FREE(loutPublic);
    if (creationData != NULL)
        SAFE_FREE(*creationData);
    if (creationHash != NULL)
        SAFE_FREE(*creationHash);
    if (creationTicket != NULL)
        SAFE_FREE(*creationTicket);
    return r;
}
