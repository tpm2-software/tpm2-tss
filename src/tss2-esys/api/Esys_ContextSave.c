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
    ESYS_TR saveHandle)
{
    esysContext->in.ContextSave.saveHandle = saveHandle;
}

/** One-Call function for TPM2_ContextSave
 *
 * This function invokes the TPM2_ContextSave command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] saveHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_CONTEXT.
 * @param[out] context (callee-allocated) Output parameter
 *    of type TPMS_CONTEXT. May be NULL if this value is not required.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_ContextSave(
    ESYS_CONTEXT *esysContext,
    ESYS_TR saveHandle,
    TPMS_CONTEXT **context)
{
    TSS2_RC r = TSS2_RC_SUCCESS;

    r = Esys_ContextSave_async(esysContext,
                saveHandle);
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
        r = Esys_ContextSave_finish(esysContext,
                context);
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

/** Asynchronous function for TPM2_ContextSave
 *
 * This function invokes the TPM2_ContextSave command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_ContextSave_finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] saveHandle Input handle of type ESYS_TR for
 *     object with handle type TPMI_DH_CONTEXT.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_ContextSave_async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR saveHandle)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    RSRC_NODE_T *saveHandleNode;

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;

    store_input_parameters(esysContext, saveHandle);
    r = esys_GetResourceObject(esysContext, saveHandle, &saveHandleNode);
    if (r != TPM2_RC_SUCCESS)
        return r;
    r = Tss2_Sys_ContextSave_Prepare(esysContext->sys,
                (saveHandleNode == NULL) ? TPM2_RH_NULL : saveHandleNode->rsrc.handle);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error async ContextSave");
        return r;
    }
    r = Tss2_Sys_ExecuteAsync(esysContext->sys);
    return_if_error(r, "Finish (Execute Async)");

    esysContext->state = _ESYS_STATE_SENT;

    return r;
}

/** Asynchronous finish function for TPM2_ContextSave
 *
 * This function returns the results of a TPM2_ContextSave command
 * invoked via Esys_ContextSave_finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[out] context (callee-allocated) Output parameter
 *    of type TPMS_CONTEXT. May be NULL if this value is not required.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function.
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_ContextSave_finish(
    ESYS_CONTEXT *esysContext,
    TPMS_CONTEXT **context)
{
    TPMS_CONTEXT *lcontext = NULL;
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
    lcontext = calloc(sizeof(TPMS_CONTEXT), 1);
    if (lcontext == NULL) {
        return_error(TSS2_ESYS_RC_MEMORY, "Out of memory");
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
        r = Esys_ContextSave_async(esysContext,
                esysContext->in.ContextSave.saveHandle);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Error attempting to resubmit");
            goto error_cleanup;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        goto error_cleanup;
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) ContextSave");
        goto error_cleanup;
    }
    r = Tss2_Sys_ContextSave_Complete(esysContext->sys,
                lcontext);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) ContextSave: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_ERRORRESPONSE;
        goto error_cleanup;;
    }

    IESYS_CONTEXT_DATA esyscontextData;
    RSRC_NODE_T *esys_object;
    size_t offset = 0;
    esyscontextData.reserved = 0;
    memcpy(&esyscontextData.tpmContext.buffer[0], &(lcontext)->contextBlob.buffer[0],
           (lcontext)->contextBlob.size);
    esyscontextData.tpmContext.size = (lcontext)->contextBlob.size;
    r =  esys_GetResourceObject(esysContext, esysContext->in.ContextSave.saveHandle,
                                &esys_object);
    goto_if_error(r, "Error GetResourceObjectn", error_cleanup);

    esyscontextData.esysMetadata.size = 0;
    esyscontextData.esysMetadata.data = esys_object->rsrc;
    offset = 0;
    r = Tss2_MU_IESYS_CONTEXT_DATA_Marshal(&esyscontextData,
                                              &(lcontext)->contextBlob.buffer[0],
                                              sizeof(TPMS_CONTEXT_DATA), &offset);
    goto_if_error(r, "while marshaling context ", error_cleanup);

    (lcontext)->contextBlob.size = offset;
    /*
     * If the ESYS_TR object being saved refers to a session,
     * the ESYS_TR object is invalidated.
     */
    if (esys_object->rsrc.rsrcType == IESYSC_SESSION_RSRC) {
        r = Esys_TR_Close(esysContext,  &esysContext->in.ContextSave.saveHandle);
        goto_if_error(r, "invalidate object", error_cleanup);
    }
    if (context != NULL)
        *context = lcontext;
    else
        SAFE_FREE(lcontext);

    esysContext->state = _ESYS_STATE_FINISHED;

    return r;

error_cleanup:
    SAFE_FREE(lcontext);
    return r;
}
