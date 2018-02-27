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
#if defined __linux__ || defined __GNU__ || defined __GLIBC__
#define _DEFAULT_SOURCE 1
#else
#define _BSD_SOURCE 1
#define _SVID_SOURCE 1
#endif

#include "sapi/tpm20.h"
#ifndef TSS2_API_VERSION_1_2_1_108
#error Version missmatch among TSS2 header files !
#endif /* TSS2_API_VERSION_1_2_1_108 */

#include <sysapi_util.h>
#include <sapi/tss2_mu.h>
#include <inttypes.h>

#include "tss2_esys.h"
#include "esys_mu.h"
#define LOGMODULE esys_types
#include "log/log.h"

/**
 * Marshal an array of BYTE structures into a byte buffer.
 * @param[in] in Structures to be marshalled.
 * @param[in] count Number of structures to be marshalled.
 * @param[in,out] buffer Buffer to write result into.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
iesys_MU_BYTE_array_Marshal(
    const BYTE *src,
    size_t count,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%p count=%zu buffer=%p size=%zu offset=%p", src,
        count, buffer, size, offset);
    if (src == NULL) {
        LOG_ERROR("src=NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    size_t offset_loc = (offset != NULL)? *offset : 0;

    if (count > size || size - count < offset_loc) {
        LOG_ERROR("not enough space in target buffer");
        return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;
    }

    if (buffer != NULL)
        memcpy(&buffer[offset_loc], src, count);
    offset_loc += count;

    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Unmarshal an array of BYTE structures from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[in] count Number of structures to be unmarshalled.
 * @param[out] out Structures to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if buffer==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
iesys_MU_BYTE_array_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    size_t count,
    BYTE *dst)
{
    LOG_TRACE("called: count=%zu buffer=%p size=%zu offset=%p dst=%p",
        count, buffer, size, offset, dst);
    if (buffer == NULL) {
        LOG_ERROR("buffer=NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    size_t offset_loc = (offset != NULL)? *offset : 0;

    if (count > size || size - count < offset_loc) {
        LOG_ERROR("not enough space in target buffer");
        return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;
    }

    if (dst != NULL)
        memcpy(dst, &buffer[offset_loc], count);
    offset_loc += count;

    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Marshal a constant of type IESYSC_RESOURCE_TYPE_CONSTANT into a byte buffer.
 * @param[in] src constant to be marshalled.
 * @param[in,out] buffer Buffer to write result into (may be NULL)
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer (may be NULL.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_CONSTANT_Marshal(
    const IESYSC_RESOURCE_TYPE_CONSTANT src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%"PRIx32 " buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    return Tss2_MU_UINT32_Marshal(src, buffer, size, offset);
}

/**
 * Unmarshal a constant of type IESYSC_RESOURCE_TYPE_CONSTANT from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] dst variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_CONSTANT_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_RESOURCE_TYPE_CONSTANT *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    size_t offset_loc = (offset != NULL)? *offset : 0;
    IESYSC_RESOURCE_TYPE_CONSTANT dst_loc;
    TSS2_RC ret = Tss2_MU_UINT32_Unmarshal(buffer, size,
        &offset_loc, &dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Unmarshaling the base type");
        return ret;
    }
    ret = Tss2_MU_IESYSC_RESOURCE_TYPE_CONSTANT_check(&dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Bad value %"PRIx32 "", dst_loc);
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    if (dst != NULL)
        *dst = dst_loc;
    LOG_TRACE("return: dst=%p value=%"PRIx32 "", dst, dst_loc);
    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable has a possible value of type IESYSC_RESOURCE_TYPE_CONSTANT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_CONSTANT_check(
    const IESYSC_RESOURCE_TYPE_CONSTANT *in)
{
    LOG_TRACE("called: in=%p", in);
    if (in == NULL) {
        LOG_ERROR("in==NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    /* No Error-Messages, since this function may fail for a good reasons. */
    if (FALSE
        || (*in == IESYSC_KEY_RSRC)
        || (*in == IESYSC_NV_RSRC)
        || (*in == IESYSC_SESSION_RSRC)
        || (*in == IESYSC_WITHOUT_MISC_RSRC)) {
        return TSS2_RC_SUCCESS;
    } else {
        return TSS2_SYS_RC_BAD_VALUE;
    }
    return TSS2_RC_SUCCESS;
}
/**
 * Marshal a constant of type IESYSC_PARAM_ENCRYPT into a byte buffer.
 * @param[in] src constant to be marshalled.
 * @param[in,out] buffer Buffer to write result into (may be NULL)
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer (may be NULL.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYSC_PARAM_ENCRYPT_Marshal(
    const IESYSC_PARAM_ENCRYPT src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%"PRIx32 " buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    return Tss2_MU_UINT32_Marshal(src, buffer, size, offset);
}

/**
 * Unmarshal a constant of type IESYSC_PARAM_ENCRYPT from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] dst variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_PARAM_ENCRYPT_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_PARAM_ENCRYPT *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    size_t offset_loc = (offset != NULL)? *offset : 0;
    IESYSC_PARAM_ENCRYPT dst_loc;
    TSS2_RC ret = Tss2_MU_UINT32_Unmarshal(buffer, size,
        &offset_loc, &dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Unmarshaling the base type");
        return ret;
    }
    ret = Tss2_MU_IESYSC_PARAM_ENCRYPT_check(&dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Bad value %"PRIx32 "", dst_loc);
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    if (dst != NULL)
        *dst = dst_loc;
    LOG_TRACE("return: dst=%p value=%"PRIx32 "", dst, dst_loc);
    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable has a possible value of type IESYSC_PARAM_ENCRYPT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_PARAM_ENCRYPT_check(
    const IESYSC_PARAM_ENCRYPT *in)
{
    LOG_TRACE("called: in=%p", in);
    if (in == NULL) {
        LOG_ERROR("in==NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    /* No Error-Messages, since this function may fail for a good reasons. */
    if (FALSE
        || (*in == ENCRYPT)
        || (*in == NO_ENCRYPT)) {
        return TSS2_RC_SUCCESS;
    } else {
        return TSS2_SYS_RC_BAD_VALUE;
    }
    return TSS2_RC_SUCCESS;
}
/**
 * Marshal a constant of type IESYSC_PARAM_DECRYPT into a byte buffer.
 * @param[in] src constant to be marshalled.
 * @param[in,out] buffer Buffer to write result into (may be NULL)
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer (may be NULL.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYSC_PARAM_DECRYPT_Marshal(
    const IESYSC_PARAM_DECRYPT src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%"PRIx32 " buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    return Tss2_MU_UINT32_Marshal(src, buffer, size, offset);
}

/**
 * Unmarshal a constant of type IESYSC_PARAM_DECRYPT from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] dst variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_PARAM_DECRYPT_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_PARAM_DECRYPT *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    size_t offset_loc = (offset != NULL)? *offset : 0;
    IESYSC_PARAM_DECRYPT dst_loc;
    TSS2_RC ret = Tss2_MU_UINT32_Unmarshal(buffer, size,
        &offset_loc, &dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Unmarshaling the base type");
        return ret;
    }
    ret = Tss2_MU_IESYSC_PARAM_DECRYPT_check(&dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Bad value %"PRIx32 "", dst_loc);
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    if (dst != NULL)
        *dst = dst_loc;
    LOG_TRACE("return: dst=%p value=%"PRIx32 "", dst, dst_loc);
    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable has a possible value of type IESYSC_PARAM_DECRYPT.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_PARAM_DECRYPT_check(
    const IESYSC_PARAM_DECRYPT *in)
{
    LOG_TRACE("called: in=%p", in);
    if (in == NULL) {
        LOG_ERROR("in==NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    /* No Error-Messages, since this function may fail for a good reasons. */
    if (FALSE
        || (*in == DECRYPT)
        || (*in == NO_DECRYPT)) {
        return TSS2_RC_SUCCESS;
    } else {
        return TSS2_SYS_RC_BAD_VALUE;
    }
    return TSS2_RC_SUCCESS;
}
/**
 * Marshal a constant of type IESYSC_TYPE_POLICY_AUTH into a byte buffer.
 * @param[in] src constant to be marshalled.
 * @param[in,out] buffer Buffer to write result into (may be NULL)
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer (may be NULL.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYSC_TYPE_POLICY_AUTH_Marshal(
    const IESYSC_TYPE_POLICY_AUTH src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%"PRIx32 " buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    return Tss2_MU_UINT32_Marshal(src, buffer, size, offset);
}

/**
 * Unmarshal a constant of type IESYSC_TYPE_POLICY_AUTH from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] dst variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_TYPE_POLICY_AUTH_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_TYPE_POLICY_AUTH *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    size_t offset_loc = (offset != NULL)? *offset : 0;
    IESYSC_TYPE_POLICY_AUTH dst_loc;
    TSS2_RC ret = Tss2_MU_UINT32_Unmarshal(buffer, size,
        &offset_loc, &dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Unmarshaling the base type");
        return ret;
    }
    ret = Tss2_MU_IESYSC_TYPE_POLICY_AUTH_check(&dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Bad value %"PRIx32 "", dst_loc);
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    if (dst != NULL)
        *dst = dst_loc;
    LOG_TRACE("return: dst=%p value=%"PRIx32 "", dst, dst_loc);
    return TSS2_RC_SUCCESS;
}

/**
 * Check, if a variable has a possible value of type IESYSC_TYPE_POLICY_AUTH.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_TYPE_POLICY_AUTH_check(
    const IESYSC_TYPE_POLICY_AUTH *in)
{
    LOG_TRACE("called: in=%p", in);
    if (in == NULL) {
        LOG_ERROR("in==NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    /* No Error-Messages, since this function may fail for a good reasons. */
    if (FALSE
        || (*in == POLICY_PASSWORD)
        || (*in == POLICY_AUTH)
        || (*in == NO_POLICY_AUTH)) {
        return TSS2_RC_SUCCESS;
    } else {
        return TSS2_SYS_RC_BAD_VALUE;
    }
    return TSS2_RC_SUCCESS;
}

/**
 * Marshal a IESYS_SESSION structure into a byte buffer.
 * @param[in] src variable to be marshalled.
 * @param[in,out] buffer Buffer to write result into.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_SESSION_Marshal(
    const IESYS_SESSION *src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%p buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    if (src == NULL) {
        LOG_ERROR("src=NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret;
    size_t offset_loc = (offset != NULL)? *offset : 0;
    ret = Tss2_MU_TPM2B_NAME_Marshal(&src->bound_entity, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield bound_entity");
        return ret;
    }
    ret = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Marshal(&src->encryptedSalt, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield encryptedSalt");
        return ret;
    }
    ret = Tss2_MU_TPM2B_DATA_Marshal(&src->salt, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield salt");
        return ret;
    }
    ret = Tss2_MU_TPMT_SYM_DEF_Marshal(&src->symmetric, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield symmetric");
        return ret;
    }
    ret = Tss2_MU_TPMI_ALG_HASH_Marshal(src->authHash, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield authHash");
        return ret;
    }
    ret = Tss2_MU_TPM2B_DIGEST_Marshal(&src->sessionKey, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield sessionKey");
        return ret;
    }
    ret = Tss2_MU_TPM2_SE_Marshal(src->sessionType, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield sessionType");
        return ret;
    }
    ret = Tss2_MU_TPMA_SESSION_Marshal(src->sessionAttributes, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield sessionAttributes");
        return ret;
    }
    ret = Tss2_MU_TPM2B_NONCE_Marshal(&src->nonceCaller, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield nonceCaller");
        return ret;
    }
    ret = Tss2_MU_TPM2B_NONCE_Marshal(&src->nonceTPM, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield nonceTPM");
        return ret;
    }
    ret = Tss2_MU_IESYSC_PARAM_ENCRYPT_Marshal(src->encrypt, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield encrypt");
        return ret;
    }
    ret = Tss2_MU_IESYSC_PARAM_ENCRYPT_Marshal(src->decrypt, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield decrypt");
        return ret;
    }
    ret = Tss2_MU_IESYSC_TYPE_POLICY_AUTH_Marshal(src->type_policy_session, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield type_policy_session");
        return ret;
    }
    ret = Tss2_MU_UINT16_Marshal(src->sizeSessionValue, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield sizeSessionValue");
        return ret;
    }
    ret = iesys_MU_BYTE_array_Marshal(&src->sessionValue[0], src->sizeSessionValue,
        buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield sessionValue");
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Unmarshal a IESYS_SESSION variable from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] out variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if buffer==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_SESSION_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYS_SESSION *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    if (buffer == NULL) {
        LOG_ERROR("buffer=NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret;
    size_t offset_loc = (offset != NULL)? *offset : 0;
    ret = Tss2_MU_TPM2B_NAME_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->bound_entity);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield bound_entity");
        return ret;
    }
    ret = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->encryptedSalt);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield encryptedSalt");
        return ret;
    }
    ret = Tss2_MU_TPM2B_DATA_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->salt);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield salt");
        return ret;
    }
    ret = Tss2_MU_TPMT_SYM_DEF_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->symmetric);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield symmetric");
        return ret;
    }
    TPMI_ALG_HASH out_authHash;
    ret = Tss2_MU_TPMI_ALG_HASH_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_authHash : &dst->authHash);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield authHash");
        return ret;
    }
    ret = Tss2_MU_TPM2B_DIGEST_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->sessionKey);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield sessionKey");
        return ret;
    }
    TPM2_SE out_sessionType;
    ret = Tss2_MU_TPM2_SE_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_sessionType : &dst->sessionType);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield sessionType");
        return ret;
    }
    TPMA_SESSION out_sessionAttributes;
    ret = Tss2_MU_TPMA_SESSION_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_sessionAttributes : &dst->sessionAttributes);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield sessionAttributes");
        return ret;
    }
    ret = Tss2_MU_TPM2B_NONCE_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->nonceCaller);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield nonceCaller");
        return ret;
    }
    ret = Tss2_MU_TPM2B_NONCE_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->nonceTPM);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield nonceTPM");
        return ret;
    }
    IESYSC_PARAM_ENCRYPT out_encrypt;
    ret = Tss2_MU_IESYSC_PARAM_ENCRYPT_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_encrypt : &dst->encrypt);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield encrypt");
        return ret;
    }
    IESYSC_PARAM_ENCRYPT out_decrypt;
    ret = Tss2_MU_IESYSC_PARAM_ENCRYPT_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_decrypt : &dst->decrypt);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield decrypt");
        return ret;
    }
    IESYSC_TYPE_POLICY_AUTH out_type_policy_session;
    ret = Tss2_MU_IESYSC_TYPE_POLICY_AUTH_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_type_policy_session : &dst->type_policy_session);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield type_policy_session");
        return ret;
    }
    UINT16 out_sizeSessionValue;
    ret = Tss2_MU_UINT16_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_sizeSessionValue : &dst->sizeSessionValue);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield sizeSessionValue");
        return ret;
    }
    ret = iesys_MU_BYTE_array_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? out_sizeSessionValue : dst->sizeSessionValue,
            (dst == NULL)? NULL : &dst->sessionValue[0]);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield sessionValue");
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Marshal a IESYSC_RESOURCE_TYPE type into a byte buffer.
 * @param[in] src constant to be marshalled.
 * @param[in,out] buffer Buffer to write result into (may be NULL)
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer (may be NULL.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_Marshal(
    const IESYSC_RESOURCE_TYPE src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%"PRIx32 " buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    return Tss2_MU_UINT32_Marshal(src, buffer, size, offset);
}

/**
 * Unmarshal a IESYSC_RESOURCE_TYPE type from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] dst variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYSC_RESOURCE_TYPE *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    IESYSC_RESOURCE_TYPE dst_loc;
    TSS2_RC ret = Tss2_MU_UINT32_Unmarshal(buffer, size,
        offset, &dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Unmarshaling the base type");
        return ret;
    }
    ret = Tss2_MU_IESYSC_RESOURCE_TYPE_check(&dst_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Bad value %"PRIx32 "", dst_loc);
        return ret;
    }
    if (dst != NULL)
        *dst = dst_loc;
    LOG_TRACE("return: dst=%p value=%"PRIx32 "", dst, dst_loc);
    return TSS2_RC_SUCCESS;
}


/**
 * Check, if a variable has a possible value of type IESYSC_RESOURCE_TYPE.
 * @param[in] in variable to check.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
Tss2_MU_IESYSC_RESOURCE_TYPE_check(
    const IESYSC_RESOURCE_TYPE *in)
{
    LOG_TRACE("called: in=%p", in);
    if (in == NULL) {
        LOG_ERROR("in==NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    /* No Error-Messages, since this function may fail for a good reasons. */
    if (FALSE
            || (*in == IESYSC_KEY_RSRC)
            || (*in == IESYSC_NV_RSRC)
            || (*in == IESYSC_SESSION_RSRC)
            || (*in == IESYSC_WITHOUT_MISC_RSRC)) {
        return TSS2_RC_SUCCESS;
    } else {
        return TSS2_SYS_RC_BAD_VALUE;
    }
    return TSS2_RC_SUCCESS;
}

/**
 * Marshal a IESYS_RSRC_UNION union into a byte buffer.
 * @param[in] src variable to be marshalled.
 * @param[in] selector the selector value.
 * @param[in,out] buffer Buffer to write result into.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_RSRC_UNION_Marshal(
    const IESYS_RSRC_UNION *src,
    UINT32 selector,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%p buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    if (src == NULL) {
        LOG_ERROR("src=NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    switch (selector) {
    case IESYSC_KEY_RSRC:
        return Tss2_MU_TPM2B_PUBLIC_Marshal(&src->rsrc_key_pub, buffer, size, offset);
    case IESYSC_NV_RSRC:
        return Tss2_MU_TPM2B_NV_PUBLIC_Marshal(&src->rsrc_nv_pub, buffer, size, offset);
    case IESYSC_SESSION_RSRC:
        return Tss2_MU_IESYS_SESSION_Marshal(&src->rsrc_session, buffer, size, offset);
    case IESYSC_WITHOUT_MISC_RSRC:
        return Tss2_MU_TPMS_EMPTY_Marshal(&src->rsrc_empty, buffer, size, offset);
    default:
        LOG_ERROR("Selector value %"PRIu32 " not found", selector);
        return TSS2_SYS_RC_BAD_VALUE;
    };
}

/**
 * Unmarshal a IESYS_RSRC_UNION union from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer (may be NULL).
 * @param[in] selector The selector.
 * @param[out] out variable to store the result in (may be NULL).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_RSRC_UNION_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    UINT32 selector,
    IESYS_RSRC_UNION *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    if (buffer == NULL) {
        LOG_ERROR("buffer=NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    switch (selector) {
    case IESYSC_KEY_RSRC:
        return Tss2_MU_TPM2B_PUBLIC_Unmarshal(buffer, size, offset,
                   (dst != NULL)? &dst->rsrc_key_pub : NULL);
    case IESYSC_NV_RSRC:
        return Tss2_MU_TPM2B_NV_PUBLIC_Unmarshal(buffer, size, offset,
                   (dst != NULL)? &dst->rsrc_nv_pub : NULL);
    case IESYSC_SESSION_RSRC:
        return Tss2_MU_IESYS_SESSION_Unmarshal(buffer, size, offset,
                   (dst != NULL)? &dst->rsrc_session : NULL);
    case IESYSC_WITHOUT_MISC_RSRC:
        return Tss2_MU_TPMS_EMPTY_Unmarshal(buffer, size, offset,
                   (dst != NULL)? &dst->rsrc_empty : NULL);
    default:
        LOG_ERROR("Selector value %"PRIu32 " not found", selector);
        return TSS2_SYS_RC_BAD_VALUE;
    };
}

/**
 * Marshal a IESYS_RESOURCE structure into a byte buffer.
 * @param[in] src variable to be marshalled.
 * @param[in,out] buffer Buffer to write result into.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_RESOURCE_Marshal(
    const IESYS_RESOURCE *src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%p buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    if (src == NULL) {
        LOG_ERROR("src=NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret;
    size_t offset_loc = (offset != NULL)? *offset : 0;
    ret = Tss2_MU_TPM2_HANDLE_Marshal(src->handle, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield handle");
        return ret;
    }
    ret = Tss2_MU_TPM2B_NAME_Marshal(&src->name, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield name");
        return ret;
    }
    ret = Tss2_MU_BYTE_Marshal(src->authValueSet, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield authValueSet");
        return ret;
    }
    ret = Tss2_MU_IESYSC_RESOURCE_TYPE_Marshal(src->rsrcType, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield rsrcType");
        return ret;
    }
    ret = Tss2_MU_IESYS_RSRC_UNION_Marshal(&src->misc, src->rsrcType,
        buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield misc");
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Unmarshal a IESYS_RESOURCE variable from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] out variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if buffer==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_RESOURCE_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYS_RESOURCE *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    if (buffer == NULL) {
        LOG_ERROR("buffer=NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret;
    size_t offset_loc = (offset != NULL)? *offset : 0;
    TPM2_HANDLE out_handle;
    ret = Tss2_MU_TPM2_HANDLE_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_handle : &dst->handle);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield handle");
        return ret;
    }
    ret = Tss2_MU_TPM2B_NAME_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->name);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield name");
        return ret;
    }
    BYTE out_authValueSet;
    ret = Tss2_MU_BYTE_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_authValueSet : &dst->authValueSet);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield authValueSet");
        return ret;
    }
    IESYSC_RESOURCE_TYPE out_rsrcType;
    ret = Tss2_MU_IESYSC_RESOURCE_TYPE_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_rsrcType : &dst->rsrcType);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield rsrcType");
        return ret;
    }
    ret = Tss2_MU_IESYS_RSRC_UNION_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? out_rsrcType : dst->rsrcType,
            (dst == NULL)? NULL : &dst->misc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield misc");
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Marshal a IESYS_METADATA structure into a byte buffer.
 * @param[in] src variable to be marshalled.
 * @param[in,out] buffer Buffer to write result into.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_METADATA_Marshal(
    const IESYS_METADATA *src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%p buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    if (src == NULL) {
        LOG_ERROR("src=NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret;
    size_t offset_loc = (offset != NULL)? *offset : 0;
    ret = Tss2_MU_UINT16_Marshal(src->size, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield size");
        return ret;
    }
    ret = Tss2_MU_IESYS_RESOURCE_Marshal(&src->data, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield data");
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Unmarshal a IESYS_METADATA variable from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] out variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if buffer==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_METADATA_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYS_METADATA *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    if (buffer == NULL) {
        LOG_ERROR("buffer=NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret;
    size_t offset_loc = (offset != NULL)? *offset : 0;
    UINT16 out_size;
    ret = Tss2_MU_UINT16_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_size : &dst->size);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield size");
        return ret;
    }
    IESYS_RESOURCE out_data;
    ret = Tss2_MU_IESYS_RESOURCE_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_data : &dst->data);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield data");
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Marshal a IESYS_CONTEXT_DATA structure into a byte buffer.
 * @param[in] src variable to be marshalled.
 * @param[in,out] buffer Buffer to write result into.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if src==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_CONTEXT_DATA_Marshal(
    const IESYS_CONTEXT_DATA *src,
    uint8_t *buffer,
    size_t size,
    size_t *offset)
{
    LOG_TRACE("called: src=%p buffer=%p size=%zu offset=%p", src,
        buffer, size, offset);
    if (src == NULL) {
        LOG_ERROR("src=NULL");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret;
    size_t offset_loc = (offset != NULL)? *offset : 0;
    ret = Tss2_MU_UINT32_Marshal(src->reserved, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield reserved");
        return ret;
    }
    ret = Tss2_MU_TPM2B_CONTEXT_DATA_Marshal(&src->tpmContext, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield tpmContext");
        return ret;
    }
    ret = Tss2_MU_IESYS_METADATA_Marshal(&src->esysMetadata, buffer, size, &offset_loc);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error marshalling subfield esysMetadata");
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}

/**
 * Unmarshal a IESYS_CONTEXT_DATA variable from a byte buffer.
 * @param[in,out] buffer Buffer to read data from.
 * @param[in] size Size of the buffer.
 * @param[in,out] offset Offset inside the buffer
 *                (being updated during marshalling).
 * @param[out] out variable to store the result in.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if buffer==NULL.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_BUFFER if remaining buffer is insufficient.
 */
TSS2_RC
Tss2_MU_IESYS_CONTEXT_DATA_Unmarshal(
    const uint8_t *buffer,
    size_t size,
    size_t *offset,
    IESYS_CONTEXT_DATA *dst)
{
    LOG_TRACE("called: buffer=%p size=%zu offset=%p dst=%p",
        buffer, size, offset, dst);
    if (buffer == NULL) {
        LOG_ERROR("buffer=NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret;
    size_t offset_loc = (offset != NULL)? *offset : 0;
    UINT32 out_reserved;
    ret = Tss2_MU_UINT32_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_reserved : &dst->reserved);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield reserved");
        return ret;
    }
    ret = Tss2_MU_TPM2B_CONTEXT_DATA_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? NULL : &dst->tpmContext);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield tpmContext");
        return ret;
    }
    IESYS_METADATA out_esysMetadata;
    ret = Tss2_MU_IESYS_METADATA_Unmarshal(buffer, size, &offset_loc,
            (dst == NULL)? &out_esysMetadata : &dst->esysMetadata);
    if (ret != TSS2_RC_SUCCESS) {
        LOG_ERROR("Error unmarshalling subfield esysMetadata");
        return ret;
    }
    if (offset != NULL)
        *offset = offset_loc;
    return TSS2_RC_SUCCESS;
}