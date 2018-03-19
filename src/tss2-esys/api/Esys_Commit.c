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
    ESYS_TR signHandle,
    const TPM2B_ECC_POINT *P1,
    const TPM2B_SENSITIVE_DATA *s2,
    const TPM2B_ECC_PARAMETER *y2)
{
    esysContext->in.Commit.signHandle = signHandle;
    if (P1 == NULL) {
        esysContext->in.Commit.P1 = NULL;
    } else {
        esysContext->in.Commit.P1Data = *P1;
        esysContext->in.Commit.P1 =
            &esysContext->in.Commit.P1Data;
    }
    if (s2 == NULL) {
        esysContext->in.Commit.s2 = NULL;
    } else {
        esysContext->in.Commit.s2Data = *s2;
        esysContext->in.Commit.s2 =
            &esysContext->in.Commit.s2Data;
    }
    if (y2 == NULL) {
        esysContext->in.Commit.y2 = NULL;
    } else {
        esysContext->in.Commit.y2Data = *y2;
        esysContext->in.Commit.y2 =
            &esysContext->in.Commit.y2Data;
    }
}

/** One-Call function for TPM2_Commit
 *
 * This function invokes the TPM2_Commit command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] signHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] P1 Input parameter of type TPM2B_ECC_POINT.
 * @param[in] s2 Input parameter of type TPM2B_SENSITIVE_DATA.
 * @param[in] y2 Input parameter of type TPM2B_ECC_PARAMETER.
 * @param[out] K (callee-allocated) Output parameter
 *    of type TPM2B_ECC_POINT. May be NULL if this value is not required.
 * @param[out] L (callee-allocated) Output parameter
 *    of type TPM2B_ECC_POINT. May be NULL if this value is not required.
 * @param[out] E (callee-allocated) Output parameter
 *    of type TPM2B_ECC_POINT. May be NULL if this value is not required.
 * @param[out] counter (callee-allocated) Output parameter
 *    of type UINT16. May be NULL if this value is not required.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_Commit(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *P1,
    const TPM2B_SENSITIVE_DATA *s2,
    const TPM2B_ECC_PARAMETER *y2,
    TPM2B_ECC_POINT **K,
    TPM2B_ECC_POINT **L,
    TPM2B_ECC_POINT **E,
    UINT16 *counter)
{
    TSS2_RC r = TSS2_RC_SUCCESS;

    r = Esys_Commit_async(esysContext,
                signHandle,
                shandle1,
                shandle2,
                shandle3,
                P1,
                s2,
                y2);
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
        r = Esys_Commit_finish(esysContext,
                K,
                L,
                E,
                counter);
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

/** Asynchronous function for TPM2_Commit
 *
 * This function invokes the TPM2_Commit command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_Commit_finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] signHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_OBJECT.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] P1 Input parameter of type TPM2B_ECC_POINT.
 * @param[in] s2 Input parameter of type TPM2B_SENSITIVE_DATA.
 * @param[in] y2 Input parameter of type TPM2B_ECC_PARAMETER.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_Commit_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *P1,
    const TPM2B_SENSITIVE_DATA *s2,
    const TPM2B_ECC_PARAMETER *y2)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    TSS2L_SYS_AUTH_COMMAND auths = { 0 };
    RSRC_NODE_T *signHandleNode;

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;
    r = check_session_feasability(shandle1, shandle2, shandle3, 1);
    return_if_error(r, "Check session usage");

    store_input_parameters(esysContext, signHandle,
                P1,
                s2,
                y2);
    r = esys_GetResourceObject(esysContext, signHandle, &signHandleNode);
    if (r != TPM2_RC_SUCCESS)
        return r;
    r = Tss2_Sys_Commit_Prepare(esysContext->sys,
                (signHandleNode == NULL) ? TPM2_RH_NULL : signHandleNode->rsrc.handle,
                P1,
                s2,
                y2);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error async Commit");
        return r;
    }
    r = init_session_tab(esysContext, shandle1, shandle2, shandle3);
    return_if_error(r, "Initialize session resources");

    iesys_compute_session_value(esysContext->session_tab[0],
                &signHandleNode->rsrc.name, &signHandleNode->auth);
    iesys_compute_session_value(esysContext->session_tab[1], NULL, NULL);
    iesys_compute_session_value(esysContext->session_tab[2], NULL, NULL);
    r = iesys_gen_auths(esysContext, signHandleNode, NULL, NULL, &auths);
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

/** Asynchronous finish function for TPM2_Commit
 *
 * This function returns the results of a TPM2_Commit command
 * invoked via Esys_Commit_finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[out] K (callee-allocated) Output parameter
 *    of type TPM2B_ECC_POINT. May be NULL if this value is not required.
 * @param[out] L (callee-allocated) Output parameter
 *    of type TPM2B_ECC_POINT. May be NULL if this value is not required.
 * @param[out] E (callee-allocated) Output parameter
 *    of type TPM2B_ECC_POINT. May be NULL if this value is not required.
 * @param[out] counter (callee-allocated) Output parameter
 *    of type UINT16. May be NULL if this value is not required.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function.
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_Commit_finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **K,
    TPM2B_ECC_POINT **L,
    TPM2B_ECC_POINT **E,
    UINT16 *counter)
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
    TSS2_RC r = TSS2_RC_SUCCESS;
    if (K != NULL) {
        *K = calloc(sizeof(TPM2B_ECC_POINT), 1);
        if (*K == NULL) {
            return_error(TSS2_ESYS_RC_MEMORY, "Out of memory");
        }
    }
    if (L != NULL) {
        *L = calloc(sizeof(TPM2B_ECC_POINT), 1);
        if (*L == NULL) {
            goto_error(r, TSS2_ESYS_RC_MEMORY, "Out of memory", error_cleanup);
        }
    }
    if (E != NULL) {
        *E = calloc(sizeof(TPM2B_ECC_POINT), 1);
        if (*E == NULL) {
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
        r = Esys_Commit_async(esysContext,
                esysContext->in.Commit.signHandle,
                esysContext->session_type[0],
                esysContext->session_type[1],
                esysContext->session_type[2],
                esysContext->in.Commit.P1,
                esysContext->in.Commit.s2,
                esysContext->in.Commit.y2);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Error attempting to resubmit");
            goto error_cleanup;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        goto error_cleanup;
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) Commit");
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
    r = Tss2_Sys_Commit_Complete(esysContext->sys,
                (K != NULL) ? *K : NULL,
                (L != NULL) ? *L : NULL,
                (E != NULL) ? *E : NULL,
                counter);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) Commit: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_ERRORRESPONSE;
        goto error_cleanup;;
    }
    esysContext->state = _ESYS_STATE_FINISHED;

    return r;

error_cleanup:
    if (K != NULL)
        SAFE_FREE(*K);
    if (L != NULL)
        SAFE_FREE(*L);
    if (E != NULL)
        SAFE_FREE(*E);
    return r;
}
