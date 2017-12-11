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
    const TPMS_CONTEXT *context)
{
    if (context == NULL) {
        esysContext->in.ContextLoad.context = NULL;
    } else {
        esysContext->in.ContextLoad.contextData = *context;
        esysContext->in.ContextLoad.context =
            &esysContext->in.ContextLoad.contextData;
    }
}

/** One-Call function for TPM2_ContextLoad
 *
 * This function invokes the TPM2_ContextLoad command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] context Input parameter of type TPMS_CONTEXT.
 * @param[out] loadedHandle  ESYS_TR handle of ESYS resource for TPMI_DH_CONTEXT.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_ContextLoad(
    ESYS_CONTEXT *esysContext,
    const TPMS_CONTEXT *context,
    ESYS_TR *loadedHandle)
{
    TSS2_RC r = TSS2_RC_SUCCESS;

    r = Esys_ContextLoad_async(esysContext,
                context);
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
        r = Esys_ContextLoad_finish(esysContext,
                loadedHandle);
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

/** Asynchronous function for TPM2_ContextLoad
 *
 * This function invokes the TPM2_ContextLoad command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_ContextLoad_finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in] context Input parameter of type TPMS_CONTEXT.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_ContextLoad_async(
    ESYS_CONTEXT *esysContext,
    const TPMS_CONTEXT *context)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IESYS_CONTEXT_DATA esyscontextData;
    TPMS_CONTEXT tpmContext;

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;

    store_input_parameters(esysContext,
                context);
    size_t offset = 0;

    /* ESYS Special Handling Code: The context was extended with metadata during
       Esys_ContextSave. Here we extract the TPM-parts to pass then to the TPM.
    */
    r = Tss2_MU_IESYS_CONTEXT_DATA_Unmarshal (&context->contextBlob.buffer[0],
                                              context->contextBlob.size,
                                              &offset, &esyscontextData);
    return_if_error(r, "while unmarshaling context ");

    /* The actual contextBlob for the TPM is embedded inside the
       ESYS_CONTEXT_DATA. Some of the values at the start of TPMS_CONTEXT
       need to be kept though. */

    tpmContext.sequence = context->sequence;
    tpmContext.savedHandle = context->savedHandle;
    tpmContext.hierarchy = context->hierarchy;
    tpmContext.contextBlob = esyscontextData.tpmContext;

    /* Now we override the context parameter with the corrected version, since
       it is nowhere used beyond this point. */
    context = &tpmContext;

    r = Tss2_Sys_ContextLoad_Prepare(esysContext->sys,
                context);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error async ContextLoad");
        return r;
    }
    r = Tss2_Sys_ExecuteAsync(esysContext->sys);
    return_if_error(r, "Finish (Execute Async)");

    esysContext->state = _ESYS_STATE_SENT;

    return r;
}

/** Asynchronous finish function for TPM2_ContextLoad
 *
 * This function returns the results of a TPM2_ContextLoad command
 * invoked via Esys_ContextLoad_finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[out] loadedHandle  ESYS_TR handle of ESYS resource for TPMI_DH_CONTEXT.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RC_BAD_SEQUENCE if context is not ready for this function.
 * \todo add further error RCs to documentation
 */
TSS2_RC
Esys_ContextLoad_finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *loadedHandle)
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
    IESYS_RESOURCE *loadedHandleRsrc = NULL;
    RSRC_NODE_T *loadedHandleNode = NULL;

    if (loadedHandle == NULL) {
        LOG_ERROR("Handle loadedHandle may not be NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    *loadedHandle = esysContext->esys_handle_cnt++;
    r = esys_CreateResourceObject(esysContext, *loadedHandle, &loadedHandleNode);
    if (r != TSS2_RC_SUCCESS)
        return r;

    IESYS_CONTEXT_DATA esyscontextData;
    size_t offset = 0;
    r = Tss2_MU_IESYS_CONTEXT_DATA_Unmarshal(&esysContext->in.ContextLoad.context->contextBlob.buffer[0],
                                                 sizeof(IESYS_CONTEXT_DATA),
                                                 &offset, &esyscontextData);
    goto_if_error(r, "while unmarshaling context ", error_cleanup);

    loadedHandleNode->rsrc = esyscontextData.esysMetadata.data;

    r = Tss2_Sys_ExecuteFinish(esysContext->sys, esysContext->timeout);
    if ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN) {
        LOG_DEBUG("A layer below returned TRY_AGAIN: %" PRIx32, r);
        goto error_cleanup;
    }
    if (r == TPM2_RC_RETRY || r == TPM2_RC_TESTING || r == TPM2_RC_YIELDED) {
        LOG_DEBUG("TPM returned RETRY, TESTING or YIELDED, which triggers a "
            "resubmission: %" PRIx32, r);
        if (esysContext->submissionCount > _ESYS_MAX_SUMBISSIONS) {
            LOG_WARNING("Maximum number of resubmissions has been reached.");
            esysContext->state = _ESYS_STATE_ERRORRESPONSE;
            goto error_cleanup;
        }
        esysContext->state = _ESYS_STATE_RESUBMISSION;
        r = Esys_ContextLoad_async(esysContext,
                esysContext->in.ContextLoad.context);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Error attempting to resubmit");
            goto error_cleanup;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        goto error_cleanup;
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) ContextLoad");
        goto error_cleanup;
    }
    r = Tss2_Sys_ContextLoad_Complete(esysContext->sys,
                &loadedHandleNode->rsrc.handle);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error finish (ExecuteFinish) ContextLoad: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_ERRORRESPONSE;
        goto error_cleanup;;
    }
    esysContext->state = _ESYS_STATE_FINISHED;

    return r;

error_cleanup:
    Esys_TR_Close(esysContext, loadedHandle);
    return r;
}