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

#include <sapi/tpm20.h>
#ifndef TSS2_API_VERSION_1_1_1_1
#error Version missmatch among TSS2 header files !
#endif /* TSS2_API_VERSION_1_1_1_1 */
#include "esys_types.h"
#include <esapi/tss2_esys.h>
#include "esys_iutil.h"
#include "esys_mu.h"
#include <sapi/tss2_sys.h>
#define LOGMODULE esys
#include "log/log.h"

/** Store command parameters inside the ESYS_CONTEXT for use during _finish */
static void store_input_parameters (
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    UINT32 newMaxTries,
    UINT32 newRecoveryTime,
    UINT32 lockoutRecovery)
{
    esysContext->in.DictionaryAttackParameters.lockHandle = lockHandle;
    esysContext->in.DictionaryAttackParameters.newMaxTries = newMaxTries;
    esysContext->in.DictionaryAttackParameters.newRecoveryTime = newRecoveryTime;
    esysContext->in.DictionaryAttackParameters.lockoutRecovery = lockoutRecovery;
}

/** One-Call function for TPM2_DictionaryAttackParameters
 *
 * This function invokes the TPM2_DictionaryAttackParameters command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] lockHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_RH_LOCKOUT.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] newMaxTries Input parameter of type UINT32.
 * @param[in] newRecoveryTime Input parameter of type UINT32.
 * @param[in] lockoutRecovery Input parameter of type UINT32.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_DictionaryAttackParameters(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 newMaxTries,
    UINT32 newRecoveryTime,
    UINT32 lockoutRecovery)
{
    TSS2_RC r = TSS2_RC_SUCCESS;

    r = Esys_DictionaryAttackParameters_async(esysContext,
                lockHandle,
                shandle1,
                shandle2,
                shandle3,
                newMaxTries,
                newRecoveryTime,
                lockoutRecovery);
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
        r = Esys_DictionaryAttackParameters_finish(esysContext);
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

/** Asynchronous function for TPM2_DictionaryAttackParameters
 *
 * This function invokes the TPM2_DictionaryAttackParameters command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_DictionaryAttackParameters_finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] lockHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_RH_LOCKOUT.
 * @param[in] shandle1 First session handle.
 * @param[in] shandle2 Second session handle.
 * @param[in] shandle3 Third session handle.
 * @param[in] newMaxTries Input parameter of type UINT32.
 * @param[in] newRecoveryTime Input parameter of type UINT32.
 * @param[in] lockoutRecovery Input parameter of type UINT32.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_DictionaryAttackParameters_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 newMaxTries,
    UINT32 newRecoveryTime,
    UINT32 lockoutRecovery)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    TSS2L_SYS_AUTH_COMMAND auths = { 0 };
    RSRC_NODE_T *lockHandleNode;

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;
    r = check_session_feasability(shandle1, shandle2, shandle3, 1);
    return_if_error(r, "Check session usage");

    store_input_parameters(esysContext, lockHandle,
                newMaxTries,
                newRecoveryTime,
                lockoutRecovery);
    r = esys_GetResourceObject(esysContext, lockHandle, &lockHandleNode);
    if (r != TPM2_RC_SUCCESS)
        return r;
    r = Tss2_Sys_DictionaryAttackParameters_Prepare(esysContext->sys,
                (lockHandleNode == NULL) ? TPM2_RH_NULL : lockHandleNode->rsrc.handle,
                newMaxTries,
                newRecoveryTime,
                lockoutRecovery);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error async DictionaryAttackParameters");
        return r;
    }
    r = init_session_tab(esysContext, shandle1, shandle2, shandle3);
    return_if_error(r, "Initialize session resources");

    iesys_compute_session_value(esysContext->session_tab[0],
                &lockHandleNode->rsrc.name, &lockHandleNode->auth);
    iesys_compute_session_value(esysContext->session_tab[1], NULL, NULL);
    iesys_compute_session_value(esysContext->session_tab[2], NULL, NULL);
    r = iesys_gen_auths(esysContext, lockHandleNode, NULL, NULL, &auths);
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

/** Asynchronous finish function for TPM2_DictionaryAttackParameters
 *
 * This function returns the results of a TPM2_DictionaryAttackParameters command
 * invoked via Esys_DictionaryAttackParameters_finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function.
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_DictionaryAttackParameters_finish(
    ESYS_CONTEXT *esysContext)
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
    r = Tss2_Sys_ExecuteFinish(esysContext->sys, esysContext->timeout);
    if ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN) {
        LOG_DEBUG("A layer below returned TRY_AGAIN: %" PRIx32, r);
        return r;
    }
    if (r == TPM2_RC_RETRY || r == TPM2_RC_TESTING || r == TPM2_RC_YIELDED) {
        LOG_DEBUG("TPM returned RETRY, TESTING or YIELDED, which triggers a "
            "resubmission: %" PRIx32, r);
        if (esysContext->submissionCount > _ESYS_MAX_SUMBISSIONS) {
            LOG_WARNING("Maximum number of resubmissions has been reached.");
            esysContext->state = _ESYS_STATE_ERRORRESPONSE;
            return r;
        }
        esysContext->state = _ESYS_STATE_RESUBMISSION;
        r = Esys_DictionaryAttackParameters_async(esysContext,
                esysContext->in.DictionaryAttackParameters.lockHandle,
                esysContext->session_type[0],
                esysContext->session_type[1],
                esysContext->session_type[2],
                esysContext->in.DictionaryAttackParameters.newMaxTries,
                esysContext->in.DictionaryAttackParameters.newRecoveryTime,
                esysContext->in.DictionaryAttackParameters.lockoutRecovery);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Error attempting to resubmit");
            return r;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        return r;
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) DictionaryAttackParameters");
        return r;
    }
    /*
     * Now the verification of the response (hmac check) and if necessary the
     * parameter decryption have to be done
     */
    r = iesys_check_response(esysContext);
    return_if_error(r, "Error: check response");
    /*
     * After the verification of the response we call the complete function
     * to deliver the result.
     */
    r = Tss2_Sys_DictionaryAttackParameters_Complete(esysContext->sys);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) DictionaryAttackParameters: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_ERRORRESPONSE;
        return r;;
    }
    esysContext->state = _ESYS_STATE_FINISHED;

    return r;
}