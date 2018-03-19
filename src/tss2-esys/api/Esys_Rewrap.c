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
    ESYS_TR oldParent,
    ESYS_TR newParent,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed)
{
    esysContext->in.Rewrap.oldParent = oldParent;
    esysContext->in.Rewrap.newParent = newParent;
    if (inDuplicate == NULL) {
        esysContext->in.Rewrap.inDuplicate = NULL;
    } else {
        esysContext->in.Rewrap.inDuplicateData = *inDuplicate;
        esysContext->in.Rewrap.inDuplicate =
            &esysContext->in.Rewrap.inDuplicateData;
    }
    if (name == NULL) {
        esysContext->in.Rewrap.name = NULL;
    } else {
        esysContext->in.Rewrap.nameData = *name;
        esysContext->in.Rewrap.name =
            &esysContext->in.Rewrap.nameData;
    }
    if (inSymSeed == NULL) {
        esysContext->in.Rewrap.inSymSeed = NULL;
    } else {
        esysContext->in.Rewrap.inSymSeedData = *inSymSeed;
        esysContext->in.Rewrap.inSymSeed =
            &esysContext->in.Rewrap.inSymSeedData;
    }
}

/** One-Call function for TPM2_Rewrap
 *
 * This function invokes the TPM2_Rewrap command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] oldParent Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] newParent Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] inDuplicate Input parameter of type TPM2B_PRIVATE.
 * @param[in] name Input parameter of type TPM2B_NAME.
 * @param[in] inSymSeed Input parameter of type TPM2B_ENCRYPTED_SECRET.
 * @param[out] outDuplicate (callee-allocated) Output parameter
 *    of type TPM2B_PRIVATE. May be NULL if this value is not required.
 * @param[out] outSymSeed (callee-allocated) Output parameter
 *    of type TPM2B_ENCRYPTED_SECRET. May be NULL if this value is not required.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_Rewrap(
    ESYS_CONTEXT *esysContext,
    ESYS_TR oldParent,
    ESYS_TR newParent,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    TPM2B_PRIVATE **outDuplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed)
{
    TSS2_RC r;

    r = Esys_Rewrap_async(esysContext,
                oldParent,
                newParent,
                shandle1,
                shandle2,
                shandle3,
                inDuplicate,
                name,
                inSymSeed);
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
        r = Esys_Rewrap_finish(esysContext,
                outDuplicate,
                outSymSeed);
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

/** Asynchronous function for TPM2_Rewrap
 *
 * This function invokes the TPM2_Rewrap command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_Rewrap_finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] oldParent Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] newParent Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] inDuplicate Input parameter of type TPM2B_PRIVATE.
 * @param[in] name Input parameter of type TPM2B_NAME.
 * @param[in] inSymSeed Input parameter of type TPM2B_ENCRYPTED_SECRET.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_Rewrap_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR oldParent,
    ESYS_TR newParent,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed)
{
    TSS2_RC r;
    TSS2L_SYS_AUTH_COMMAND auths;
    RSRC_NODE_T *oldParentNode;
    RSRC_NODE_T *newParentNode;

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;
    r = check_session_feasability(shandle1, shandle2, shandle3, 1);
    return_if_error(r, "Check session usage");

    store_input_parameters(esysContext, oldParent, newParent,
                inDuplicate,
                name,
                inSymSeed);
    r = esys_GetResourceObject(esysContext, oldParent, &oldParentNode);
    if (r != TPM2_RC_SUCCESS)
        return r;
    r = esys_GetResourceObject(esysContext, newParent, &newParentNode);
    if (r != TPM2_RC_SUCCESS)
        return r;
    r = Tss2_Sys_Rewrap_Prepare(esysContext->sys,
                (oldParentNode == NULL) ? TPM2_RH_NULL : oldParentNode->rsrc.handle,
                (newParentNode == NULL) ? TPM2_RH_NULL : newParentNode->rsrc.handle,
                inDuplicate,
                name,
                inSymSeed);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error async Rewrap");
        return r;
    }
    r = init_session_tab(esysContext, shandle1, shandle2, shandle3);
    return_if_error(r, "Initialize session resources");

    iesys_compute_session_value(esysContext->session_tab[0],
                &oldParentNode->rsrc.name, &oldParentNode->auth);
    iesys_compute_session_value(esysContext->session_tab[1], NULL, NULL);
    iesys_compute_session_value(esysContext->session_tab[2], NULL, NULL);
    r = iesys_gen_auths(esysContext, oldParentNode, newParentNode, NULL, &auths);
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

/** Asynchronous finish function for TPM2_Rewrap
 *
 * This function returns the results of a TPM2_Rewrap command
 * invoked via Esys_Rewrap_finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[out] outDuplicate (callee-allocated) Output parameter
 *    of type TPM2B_PRIVATE. May be NULL if this value is not required.
 * @param[out] outSymSeed (callee-allocated) Output parameter
 *    of type TPM2B_ENCRYPTED_SECRET. May be NULL if this value is not required.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function.
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_Rewrap_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outDuplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed)
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
    if (outDuplicate != NULL) {
        *outDuplicate = calloc(sizeof(TPM2B_PRIVATE), 1);
        if (*outDuplicate == NULL) {
            return_error(TSS2_ESYS_RC_MEMORY, "Out of memory");
        }
    }
    if (outSymSeed != NULL) {
        *outSymSeed = calloc(sizeof(TPM2B_ENCRYPTED_SECRET), 1);
        if (*outSymSeed == NULL) {
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
        r = Esys_Rewrap_async(esysContext,
                esysContext->in.Rewrap.oldParent,
                esysContext->in.Rewrap.newParent,
                esysContext->session_type[0],
                esysContext->session_type[1],
                esysContext->session_type[2],
                esysContext->in.Rewrap.inDuplicate,
                esysContext->in.Rewrap.name,
                esysContext->in.Rewrap.inSymSeed);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Error attempting to resubmit");
            goto error_cleanup;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        goto error_cleanup;
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) Rewrap");
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
    r = Tss2_Sys_Rewrap_Complete(esysContext->sys,
                (outDuplicate != NULL) ? *outDuplicate : NULL,
                (outSymSeed != NULL) ? *outSymSeed : NULL);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) Rewrap: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_ERRORRESPONSE;
        goto error_cleanup;;
    }
    esysContext->state = _ESYS_STATE_FINISHED;

    return r;

error_cleanup:
    if (outDuplicate != NULL)
        SAFE_FREE(*outDuplicate);
    if (outSymSeed != NULL)
        SAFE_FREE(*outSymSeed);
    return r;
}
