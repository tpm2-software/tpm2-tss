/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
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
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#include "esys_tcti_default.h"
#define LOGMODULE esys
#include "util/log.h"

/** Initialize an ESYS_CONTEXT for further use.
 *
 * Initialize an ESYS_CONTEXT that holds all the state and metadata information
 * during an interaction with the TPM.
 * If not specified, load a TCTI in this order:
 *       Library libtss2-tcti-default.so (link to the preferred TCTI)
 *       Library libtss2-tcti-tabrmd.so (tabrmd)
 *       Device /dev/tpmrm0 (kernel resident resource manager)
 *       Device /dev/tpm0 (hardware TPM)
 *       TCP socket localhost:2321 (TPM simulator)
 * @param esys_context [out] The ESYS_CONTEXT.
 * @param tcti [in] The TCTI context used to connect to the TPM (may be NULL).
 * @param abiVersion [in,out] The abi version to check and the abi version
 *        supported by this implementation (may be NULL).
 * @retval TSS2_ESYS_RC_SUCCESS if the function call was a success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if esysContext is NULL.
 * @retval TSS2_ESYS_RC_MEMORY if the ESAPI cannot allocate enough memory to
 *         create the context.
 * @retval TSS2_RCs produced by lower layers of the software stack may be
 *         returned to the caller unaltered unless handled internally.
 */
TSS2_RC
Esys_Initialize(ESYS_CONTEXT ** esys_context, TSS2_TCTI_CONTEXT * tcti,
                TSS2_ABI_VERSION * abiVersion)
{
    TSS2_RC r;
    size_t syssize;

    _ESYS_ASSERT_NON_NULL(esys_context);
    *esys_context = NULL;

    /* Allocate memory for the ESYS context
     * After this errors must jump to cleanup_return instead of returning. */
    *esys_context = calloc(1, sizeof(ESYS_CONTEXT));
    return_if_null(*esys_context, "Out of memory.", TSS2_ESYS_RC_MEMORY);

    /* Allocate memory for the SYS context */
    syssize = Tss2_Sys_GetContextSize(0);
    (*esys_context)->sys = calloc(1, syssize);
    goto_if_null((*esys_context)->sys, "Error: During malloc.",
                 TSS2_ESYS_RC_MEMORY, cleanup_return);

    /* Store the application provided tcti to be return on Esys_GetTcti(). */
    (*esys_context)->tcti_app_param = tcti;

    /* This function will initialize a default tcti if necessary. */
    r = get_tcti_default(&tcti);
    goto_if_error(r, "Initializing tcti.", cleanup_return);

    /* Initialize the ESAPI */
    r = Tss2_Sys_Initialize((*esys_context)->sys, syssize, tcti, abiVersion);
    goto_if_error(r, "During syscontext initialization", cleanup_return);

    /* Use random number for initial esys handle value to provide pseudo
       namespace for handles */
    (*esys_context)->esys_handle_cnt = ESYS_TR_MIN_OBJECT + (rand() % 6000000);

    return TSS2_RC_SUCCESS;

cleanup_return:
    /* If we created the tcti ourselves, we must clean it up */
    if ((*esys_context)->tcti_app_param == NULL && tcti != NULL) {
        Tss2_Tcti_Finalize(tcti);
        free(tcti);
    }
    /* No need to finalize (*esys_context)->sys only free since
       it is the last goto in this function. */
    free((*esys_context)->sys);
    free(*esys_context);
    *esys_context = NULL;
    return r;
}

/** Finalize an ESYS_CONTEXT
 *
 * After interactions with the TPM the context holding the metadata needs to be
 * freed. Since additional internal memory allocations may have happened during
 * use of the context, it needs to be finalized correctly.
 * @param esys_context [in,out] The ESYS_CONTEXT. (will be freed and set to NULL)
 */
void
Esys_Finalize(ESYS_CONTEXT ** esys_context)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tctcontext = NULL;

    if (esys_context == NULL || *esys_context == NULL) {
        LOG_WARNING("Finalizing NULL context.");
        return;
    }

    /* Flush from TPM and free all resource objects first */
    iesys_DeleteAllResourceObjects(*esys_context);

    /* If no tcti context was provided during initialization, then we need to
       finalize the tcti context. So we retrieve here before finalizing the
       SAPI context. */
    if ((*esys_context)->tcti_app_param == NULL) {
        r = Tss2_Sys_GetTctiContext((*esys_context)->sys, &tctcontext);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Internal error in Tss2_Sys_GetTctiContext.");
            tctcontext = NULL;
        }
    }

    /* Finalize the syscontext */
    Tss2_Sys_Finalize((*esys_context)->sys);
    free((*esys_context)->sys);

    /* If no tcti context was provided during initialization, then we need to
       finalize the tcti context here. */
    if (tctcontext != NULL) {
        Tss2_Tcti_Finalize(tctcontext);
        free(tctcontext);
    }

    /* Free esys_context */
    free(*esys_context);
    *esys_context = NULL;
}

/** Return the used TCTI context.
 *
 * If a tcti context was passed into Esys_Initialize then this tcti context is
 * return. If NULL was passed in, then NULL will be returned.
 * This function is useful before Esys_Finalize to retrieve the tcti context and
 * perform a clean Tss2_Tcti_Finalize.
 * @param esys_context [in] The ESYS_CONTEXT.
 * @param tcti [out] The TCTI context used to connect to the TPM (may be NULL).
 * @retval TSS2_RC_SUCCESS on Success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if esysContext or tcti is NULL.
 */
TSS2_RC
Esys_GetTcti(ESYS_CONTEXT * esys_context, TSS2_TCTI_CONTEXT ** tcti)
{
    _ESYS_ASSERT_NON_NULL(esys_context);
    _ESYS_ASSERT_NON_NULL(tcti);
    *tcti = esys_context->tcti_app_param;
    return TSS2_RC_SUCCESS;
}

/** Return the poll handles of the used TCTI.
 *
 * The connection to the TPM is held using a TCTI. These may optionally provide
 * handles that can be used to poll for incoming data. This is useful when
 * using the asynchronous function of ESAPI in an event-loop model.
 * @param esys_context [in] The ESYS_CONTEXT.
 * @param handles [out] The poll handles (callee-allocated, use free())
 * @param count [out] The number of poll handles.
 * @retval TSS2_RC_SUCCESS on Success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if esysContext, handles or count is NULL.
 * @retval TSS2_RCs produced by lower layers of the software stack.
 */
TSS2_RC
Esys_GetPollHandles(ESYS_CONTEXT * esys_context,
                    TSS2_TCTI_POLL_HANDLE ** handles, size_t * count)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti_context;

    _ESYS_ASSERT_NON_NULL(esys_context);
    _ESYS_ASSERT_NON_NULL(handles);
    _ESYS_ASSERT_NON_NULL(count);

    /* Get the tcti-context to use */
    r = Tss2_Sys_GetTctiContext(esys_context->sys, &tcti_context);
    return_if_error(r, "Invalid SAPI or TCTI context.");

    /* Allocate the memory to hold the poll handles */
    r = Tss2_Tcti_GetPollHandles(tcti_context, NULL, count);
    return_if_error(r, "Error getting poll handle count.");
    *handles = calloc(*count, sizeof(TSS2_TCTI_POLL_HANDLE));
    return_if_null(*handles, "Out of memory.", TSS2_ESYS_RC_MEMORY);

    /* Retrieve the poll handles */
    r = Tss2_Tcti_GetPollHandles(tcti_context, *handles, count);
    return_if_error(r, "Error getting poll handles.");
    return r;
}

/** Set the timeout of Esys asynchronous functions.
 *
 * Sets the timeout for the _finish() functions in the asynchronous versions of
 * the Esys commands.
 * @param esys_context [in] The ESYS_CONTEXT.
 * @param timeout [in] The timeout in ms or -1 to block indefinately.
 * @retval TSS2_RC_SUCCESS on Success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if esysContext is NULL.
 */
TSS2_RC
Esys_SetTimeout(ESYS_CONTEXT * esys_context, int32_t timeout)
{
    _ESYS_ASSERT_NON_NULL(esys_context);
    esys_context->timeout = timeout;
    return TSS2_RC_SUCCESS;
}
