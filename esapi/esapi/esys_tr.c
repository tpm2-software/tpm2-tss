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
#include <sapi/tpm20.h>
#ifndef TSS2_API_VERSION_1_1_1_1
#error Version missmatch among TSS2 header files !
#endif                          /* TSS2_API_VERSION_1_1_1_1 */
#include <sapi/tss2_sys.h>
#include <sapi/tss2_sys.h>
#include <sysapi_util.h>
#include "esys_types.h"
#include "esys_crypto.h"
#include <tss2_esys.h>
#define LOGMODULE esys
#include "log/log.h"
#include "esys_iutil.h"
#include "esys_mu.h"
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/** Serialization of an ESYS_TR into a byte buffer.
 *
 * Serialize the metadata of an ESYS_TR object into a byte buffer such that it
 * can be stored on disk for later use by a different program or context.
 * The serialized object can be deserialized suing Esys_TR_Deserialize.
 * @param esys_context [INOUT] The ESYS_CONTEXT.
 * @param esys_handle [IN] The ESYS_TR object to serialize.
 * @param buffer [OUT] The buffer containing the serialized metadata. (caller-callocated) Shall be free'd using free().
 * @param buffer_size [OUT] The size of the buffer parameter.
 * @retval TSS2_RC_SUCCESS on Success.
 * @retval TSS2_RC_ESYS_GENERAL_FAILURE On Failure.
 */
TSS2_RC
Esys_TR_Serialize(ESYS_CONTEXT * esys_context,
                  ESYS_TR esys_handle, uint8_t ** buffer, size_t * buffer_size)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    RSRC_NODE_T *esys_object;
    size_t offset = 0;

    r = esys_GetResourceObject(esys_context, esys_handle, &esys_object);
    return_if_error(r, "Get resource object");
    r = Tss2_MU_IESYS_RESOURCE_Marshal(&esys_object->rsrc, NULL, SIZE_MAX,
                                            buffer_size);
    return_if_error(r, "Marshal resource object");
    *buffer = malloc(*buffer_size);
    return_if_null(*buffer, "Buffer could not be allocated",
                   TSS2_ESYS_RC_MEMORY);
    r = Tss2_MU_IESYS_RESOURCE_Marshal(&esys_object->rsrc, *buffer,
                                            *buffer_size, &offset);
    return_if_error(r, "Marshal resource object");
    return TSS2_RC_SUCCESS;
};

/** Deserialization of an ESYS_TR from a byte buffer.
 *
 * Deserialize the metadata of an ESYS_TR object from a byte buffer that was
 * stored on disk for later use by a different program or context.
 * An object can be serialized suing Esys_TR_Serialize.
 * @param esys_context [INOUT] The ESYS_CONTEXT.
 * @param esys_handle [IN] The ESYS_TR object to serialize.
 * @param buffer [OUT] The buffer containing the serialized metadata. (caller-callocated) Shall be free'd using free().
 * @param buffer_size [OUT] The size of the buffer parameter.
 * @retval TSS2_RC_SUCCESS on Success \todo Add error RCs.
 * @retval TSS2_RC_ESYS_GENERAL_FAILURE On Failure.
 */
TSS2_RC
Esys_TR_Deserialize(ESYS_CONTEXT * esys_context,
                    uint8_t const *buffer,
                    size_t buffer_size, ESYS_TR * esys_handle)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    RSRC_NODE_T *esys_object;
    size_t offset = 0;

    r = esys_CreateResourceObject(esys_context, *esys_handle, &esys_object);
    return_if_error(r, "Get resource object");
    r = Tss2_MU_IESYS_RESOURCE_Unmarshal(buffer, buffer_size, &offset,
                                              &esys_object->rsrc);
    return_if_error(r, "Unmarshal resource object");
    return TSS2_RC_SUCCESS;
}

/** Start syncrounous creation of an ESYS_TR object from TPM metadata.
 *
 * This function starts the asynchronous retrieval of metadata from the TPM in
 * order to create a new ESYS_TR object.
 * @see Esys_TR_FromTPMPublic for more infomration
 */
TSS2_RC
Esys_TR_FromTPMPublic_Async(ESYS_CONTEXT * esys_context,
                            TPM2_HANDLE tpm_handle,
                            ESYS_TR shandle1,
                            ESYS_TR shandle2, ESYS_TR shandle3)
{
    TSS2_RC r;
    ESYS_TR esys_handle = esys_context->esys_handle_cnt++;
    RSRC_NODE_T *esysHandleNode = NULL;
    r = esys_CreateResourceObject(esys_context, esys_handle, &esysHandleNode);
    goto_if_error(r, "Error create resource", error_cleanup);
    esysHandleNode->rsrc.handle = tpm_handle;
    esys_context->esys_handle = esys_handle;

    if (tpm_handle >= TPM2_NV_INDEX_FIRST && tpm_handle <= TPM2_NV_INDEX_LAST) {
        esys_context->in.NV_ReadPublic.nvIndex = esys_handle;
        r = Esys_NV_ReadPublic_async(esys_context, esys_handle, shandle1,
                                     shandle2, shandle3);
        goto_if_error(r, "Error NV_ReadPublic", error_cleanup);
    } else {
        esys_context->in.ReadPublic.objectHandle = esys_handle;
        r = Esys_ReadPublic_async(esys_context, esys_handle, shandle1, shandle2,
                                  shandle3);
        goto_if_error(r, "Error ReadPublic", error_cleanup);
    }
    return r;
 error_cleanup:
    Esys_TR_Close(esys_context, &esys_handle);
    return r;
}

/** Finish asyncrounous creation of an ESYS_TR object from TPM metadata.
 * This function finishes the asynchronous retrieval of metadata from the TPM in
 * order to create a new ESYS_TR object.
 * @see Esys_TR_FromTPMPublic for more infomration
 */
TSS2_RC
Esys_TR_FromTPMPublic_Finish(ESYS_CONTEXT * esys_context, ESYS_TR * esys_handle)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    ESYS_TR objectHandle = esys_context->esys_handle;
    RSRC_NODE_T *objectHandleNode;

    r = esys_GetResourceObject(esys_context, objectHandle, &objectHandleNode);
    goto_if_error(r, "get resource", error_cleanup);
    if (objectHandleNode->rsrc.handle >= TPM2_NV_INDEX_FIRST
        && objectHandleNode->rsrc.handle <= TPM2_NV_INDEX_LAST) {
        TPM2B_NV_PUBLIC *nvPublic;
        TPM2B_NAME *nvName;
        r = Esys_NV_ReadPublic_finish(esys_context, &nvPublic, &nvName);
        goto_if_error(r, "Error NV_ReadPublic", error_cleanup);
        objectHandleNode->rsrc.rsrcType = IESYSC_NV_RSRC;
        objectHandleNode->rsrc.name = *nvName;
        objectHandleNode->rsrc.misc.rsrc_nv_pub = *nvPublic;
        SAFE_FREE(nvPublic);
        SAFE_FREE(nvName);
    } else {
        TPM2B_PUBLIC *public;
        TPM2B_NAME *name = NULL;
        TPM2B_NAME *qualifiedName = NULL;
        r = Esys_ReadPublic_finish(esys_context, &public, &name,
                                   &qualifiedName);
        goto_if_error(r, "Error ReadPublic", error_cleanup)
            objectHandleNode->rsrc.rsrcType = IESYSC_KEY_RSRC;
        objectHandleNode->rsrc.name = *name;
        objectHandleNode->rsrc.misc.rsrc_key_pub = *public;
        SAFE_FREE(public);
        SAFE_FREE(name);
            SAFE_FREE(qualifiedName);
    }
    *esys_handle = objectHandle;
    return TSS2_RC_SUCCESS;

 error_cleanup:
    Esys_TR_Close(esys_context, &objectHandle);
    return r;
}

/** Creation of an ESYS_TR object from TPM metadata.
 *
 * This function can be used to create ESYS_TR object for Tpm Resouces that are
 * not created or loaded (e.g. using ESys_CreatePrimary or ESys_Load) but
 * pre-exist inside the TPM. Examples are NV-Indices or persistent object.
 *
 * Note: For PCRs and hierarchies, please use the global ESYS_TR identifiers.
 * Note: If a session is provided the TPM is queried for the metadata twice.
 * First without a session to retrieve some metadata then with the session where
 * this metadata is used in the session HMAC calculation and thereby verified.
 *
 * Since man in the middle attacks should be prevented as much as possible it is
 * recommended to pass a session.
 * @param esys_context [INOUT] The ESYS_CONTEXT
 * @param tpm_handle [IN] The handle of the TPM object to represent as ESYS_TR.
 * @param shandle1 [INOUT] A session for securing the TPM command (optional).
 * @param shandle2 [INOUT] A session for securing the TPM command (optional).
 * @param shandle3 [INOUT] A session for securing the TPM command (optional).
 * @param object [OUT] The newly created ESYS_TR metadata object.
 * @retval TSS2_RC_SUCCESS on Success \todo Add error RCs.
 */
TSS2_RC
Esys_TR_FromTPMPublic(ESYS_CONTEXT * esys_context,
                      TPM2_HANDLE tpm_handle,
                      ESYS_TR shandle1,
                      ESYS_TR shandle2, ESYS_TR shandle3, ESYS_TR * object)
{
    TSS2_RC r;
    r = Esys_TR_FromTPMPublic_Async(esys_context, shandle1, shandle2, shandle3,
                                    tpm_handle);
    goto_if_error(r, "Error TR FromTPMPublic", error_cleanup);
    r = Esys_TR_FromTPMPublic_Finish(esys_context, object);
    goto_if_error(r, "Error TR FromTPMPublic", error_cleanup);
    return r;
 error_cleanup:
    return r;
}

/** Close an ESYS_TR without removing it from the TPM.
 *
 * This function deletes an ESYS_TR object from an ESYS_CONTEXT without deleting
 * it from the TPM. This is useful for NV-Indices or persistent keys, after
 * Esys_TR_Serialize has been called. Transient objects should be deleted using
 * Esys_FlushContext.
 * @param esys_context [INOUT] The ESYS_CONTEXT
 * @param object [OUT] ESYS_TR metadata object to be deleted from ESYS_CONTEXT.
 * @retval TSS2_RC_SUCCESS on Success \todo Add error RCs.
 */
TSS2_RC
Esys_TR_Close(ESYS_CONTEXT * esys_context, ESYS_TR * object)
{
    RSRC_NODE_T *node_rsrc;
    RSRC_NODE_T **update_node;
    for (node_rsrc = esys_context->rsrc_list, update_node =
         &esys_context->rsrc_list; node_rsrc != NULL;
         update_node = &node_rsrc, node_rsrc = node_rsrc->next) {
        if (node_rsrc->esys_handle == *object) {
            *update_node = node_rsrc->next;
            SAFE_FREE(node_rsrc);
            *object = ESYS_TR_NONE;
            return TSS2_RC_SUCCESS;
        }
    }
    LOG_ERROR("Error: Esys handle does not exist (%x).", TSS2_ESYS_RC_BAD_TR);
    return TSS2_ESYS_RC_BAD_TR;
}

/** Set the authorization value of an ESYS_TR.
 *
 * Authorization values are associated with ESYS_TR Tpm Resource object. They
 * are then picked up whenever an authorization is needed.
 *
 * Note: The authorization value is not stored in the metadata during
 * Esys_TR_Serialize. Therefor Esys_TR_SetAuth needs to be called again after
 * every Esys_TR_Deserialize.
 * @param esys_context [INOUT] The ESYS_CONTEXT.
 * @param esys_handle [INOUT] The ESYS_TR for which to set the auth value.
 * @param authValue [IN] The auth value to set for the ESYS_TR.
 * @retval TSS2_RC_SUCCESS on Success \todo Add error RCs.
 */
TSS2_RC
Esys_TR_SetAuth(ESYS_CONTEXT * esys_context, ESYS_TR esys_handle,
                TPM2B_AUTH const *authValue)
{
    IESYS_RESOURCE *rsrc;
    RSRC_NODE_T *esys_object;
    TSS2_RC r;
    r = esys_GetResourceObject(esys_context, esys_handle, &esys_object);
    if (r != TPM2_RC_SUCCESS)
        return r;
    esys_object->auth = *authValue;
    return TSS2_RC_SUCCESS;
}

/** Retrieve the TPM public name of an Esys_TR object.
 *
 * Some operations (i.e. Esys_PolicyNameHash) require the name of a TPM object
 * to be passed. Esys_TR_GetName provides this name to the caller.
 * @param esys_context [INOUT] The ESYS_CONTEXT.
 * @param esys_handle [INOUT] The ESYS_TR for which to retrieve the name.
 * @param name [OUT] The name of the object (caller-allocated; use free()).
 * @retval TSS2_RC_SUCCESS on Success \todo Add error RCs.
 */
TSS2_RC
Esys_TR_GetName(ESYS_CONTEXT * esys_context, ESYS_TR esys_handle,
                TPM2B_NAME ** name)
{
    RSRC_NODE_T *esys_object;
    TSS2_RC r = esys_GetResourceObject(esys_context, esys_handle, &esys_object);
    return_if_error(r, "Objec not found");
    *name = malloc(sizeof(TPM2B_NAME));
    if (*name == NULL) {
        LOG_ERROR("Error: out of memory");
        return TSS2_ESYS_RC_MEMORY;
    }
    if (esys_object->rsrc.rsrcType == IESYSC_KEY_RSRC) {
        r = iesys_get_name(&esys_object->rsrc.misc.rsrc_key_pub, *name);
        goto_if_error(r, "Error get name", error_cleanup);
    } else {
        if (esys_object->rsrc.rsrcType == IESYSC_NV_RSRC) {
            r = iesys_nv_get_name(&esys_object->rsrc.misc.rsrc_nv_pub, *name);
            goto_if_error(r, "Error get name", error_cleanup);
        } else {
            size_t offset = 0;
            Tss2_MU_TPM2_HANDLE_Marshal(esys_object->rsrc.handle,
                                        &(*name)->name[0], sizeof(TPM2_HANDLE),
                                        &offset);
            (*name)->size = offset;
        }
    }
    return r;
 error_cleanup:
    SAFE_FREE(name);
    return r;
}


/** Retrieve the Session Attributes of the ESYS_TR session.
 *
 * Sessions possess attributes, such as whether they shall continue of be
 * flushed after the next command, or whether they are used to encrypt
 * parameters.
 * Note: this function only applies to ESYS_TR objects that represent sessions.
 * @param esys_context [INOUT] The ESYS_CONTEXT.
 * @param esys_handle [INOUT] The ESYS_TR of the session.
 * @param flags [OUT] The attributes of the session.
 * @retval TSS2_RC_SUCCESS on Success \todo Add error RCs.
 */
TSS2_RC
Esys_TRSess_GetAttributes(ESYS_CONTEXT * esys_context, ESYS_TR esys_handle,
                          TPMA_SESSION * flags)
{
    RSRC_NODE_T *esys_object;
    TSS2_RC r = esys_GetResourceObject(esys_context, esys_handle, &esys_object);
    return_if_error(r, "Object not found");
    if (esys_object->rsrc.rsrcType != IESYSC_SESSION_RSRC)
        return_error(TSS2_ESYS_RC_BAD_TR, "Object is not a session object");
    *flags = esys_object->rsrc.misc.rsrc_session.sessionAttributes;
    return TSS2_RC_SUCCESS;
}

/** Set session attributes
 *
 * Set or unset a session's attributes according to the provieded flags and mask.
 * @verbatim new_attributes = old_attributes & ~mask | flags & mask @endverbatim
 * Note: this function only applies to ESYS_TR objects that represent sessions.
 * @param esys_context [INOUT] The ESYS_CONTEXT.
 * @param esys_handle [INOUT] The ESYS_TR of the session.
 * @param flags [IN] The flags to be set or unset for the session.
 * @param mask [IN] The mask for the flags to be set or unset.
 * @retval TSS2_RC_SUCCESS on Success \todo Add error RCs.
 */
TSS2_RC
Esys_TRSess_SetAttributes(ESYS_CONTEXT * esys_context, ESYS_TR esys_handle,
                          TPMA_SESSION flags, TPMA_SESSION mask)
{
    RSRC_NODE_T *esys_object;
    TSS2_RC r = esys_GetResourceObject(esys_context, esys_handle, &esys_object);
    return_if_error(r, "Object not found");
    if (esys_object->rsrc.rsrcType != IESYSC_SESSION_RSRC)
        return_error(TSS2_ESYS_RC_BAD_TR, "Object is not a session object");
    esys_object->rsrc.misc.rsrc_session.sessionAttributes =
        (esys_object->rsrc.misc.rsrc_session.
         sessionAttributes & ~mask) | (flags & mask);
    return TSS2_RC_SUCCESS;
}
