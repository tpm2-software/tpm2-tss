/***********************************************************************
 * Copyright (c) 2015 - 2017, Intel Corporation
 *
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
 ***********************************************************************/

#include <inttypes.h>
#include <string.h>

#include "sapi/tss2_mu.h"
#include "sapi/tpm20.h"
#include "tss2_endian.h"
#include "log.h"

#define TPM2B_MARSHAL(type) \
TSS2_RC Tss2_MU_##type##_Marshal(type const *src, uint8_t buffer[], \
                                 size_t buffer_size, size_t *offset) \
{ \
    size_t local_offset = 0; \
    TSS2_RC rc; \
\
    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } \
    if (offset != NULL) { \
        LOG (DEBUG, "offset non-NULL, initial value: %zu", *offset); \
        local_offset = *offset; \
    } \
    if (buffer == NULL && offset == NULL) { \
        LOG (WARNING, "buffer and offset parameter are NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } else if (buffer == NULL && offset != NULL) { \
        *offset += sizeof(src->size) + src->size; \
        LOG (INFO, "buffer NULL and offset non-NULL, updating offset to %zu", \
             *offset); \
        return TSS2_RC_SUCCESS; \
    } else if (buffer_size < local_offset || \
               buffer_size - local_offset < (sizeof(src->size) + src->size)) { \
        LOG (WARNING, \
             "buffer_size: %zu with offset: %zu are insufficient for object " \
             "of size %zu", \
             buffer_size, \
             local_offset, \
             sizeof(src->size) + src->size); \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", \
         (uintptr_t)&src, \
         (uintptr_t)buffer, \
         local_offset); \
\
    rc = Tss2_MU_UINT16_Marshal(src->size, buffer, buffer_size, &local_offset); \
    if (rc) \
        return rc; \
\
    if (src->size) { \
        memcpy(&buffer[local_offset], ((TPM2B *)src)->buffer, src->size); \
        local_offset += src->size; \
    } \
\
    if (offset != NULL) { \
        *offset = local_offset; \
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset); \
    } \
\
    return TSS2_RC_SUCCESS; \
}

#define TPM2B_UNMARSHAL(type) \
TSS2_RC Tss2_MU_##type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, \
                                   size_t *offset, type *dest) \
{ \
    size_t  local_offset = 0; \
    UINT16 size = 0; \
    TSS2_RC rc; \
\
    if (offset != NULL) { \
        LOG (DEBUG, "offset non-NULL, initial value: %zu", *offset); \
        local_offset = *offset; \
    } \
\
    if (buffer == NULL || (dest == NULL && offset == NULL)) { \
        LOG (WARNING, "buffer or dest and offset parameter are NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } else if (buffer_size < local_offset || \
               sizeof(size) > buffer_size - local_offset) \
    { \
        LOG (WARNING, \
             "buffer_size: %zu with offset: %zu are insufficient for object " \
             "of size %zu", \
             buffer_size, \
             local_offset, \
             sizeof(size)); \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", \
         (uintptr_t)buffer, \
         (uintptr_t)dest, \
         local_offset); \
\
    rc = Tss2_MU_UINT16_Unmarshal(buffer, buffer_size, &local_offset, &size); \
    if (rc) \
        return rc; \
\
    if (size > buffer_size - local_offset) { \
        LOG (WARNING, \
             "buffer_size: %zu with offset: %zu are insufficient for object " \
             "of size %zu", \
             buffer_size, \
             local_offset, \
             (size_t)size); \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
    if (dest != NULL) { \
        dest->size = size; \
        memcpy(((TPM2B *)dest)->buffer, &buffer[local_offset], size); \
    } \
    local_offset += size; \
    if (offset != NULL) { \
        *offset = local_offset; \
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset); \
    } \
\
    return TSS2_RC_SUCCESS; \
}

#define TPM2B_MARSHAL_SUBTYPE(type, subtype, member) \
TSS2_RC Tss2_MU_##type##_Marshal(type const *src, uint8_t buffer[], \
                                 size_t buffer_size, size_t *offset) \
{ \
    size_t local_offset = 0; \
    UINT8 *ptr; \
    TSS2_RC rc; \
\
    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } \
\
    if (offset != NULL) { \
        LOG (DEBUG, "offset non-NULL, initial value: %zu", *offset); \
        local_offset = *offset; \
    } \
\
    if (buffer == NULL && offset == NULL) { \
        LOG (WARNING, "buffer and offset parameter are NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } else if (buffer == NULL && offset != NULL) { \
        *offset += sizeof(src->size) + src->size; \
        LOG (INFO, "buffer NULL and offset non-NULL, updating offset to %zu", \
             *offset); \
        return TSS2_RC_SUCCESS; \
    } else if (buffer_size < local_offset || \
               buffer_size - local_offset < sizeof(src->size)) { \
        LOG (WARNING, \
             "buffer_size: %zu with offset: %zu are insufficient for object " \
             "of size %zu", \
             buffer_size, \
             local_offset, \
             sizeof(src->size)); \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
\
    ptr = &buffer[local_offset]; \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", \
         (uintptr_t)&src, \
         (uintptr_t)buffer, \
         local_offset); \
\
    rc = Tss2_MU_UINT16_Marshal(src->size, buffer, buffer_size, &local_offset); \
    if (rc) \
        return rc; \
\
    rc = Tss2_MU_##subtype##_Marshal(&src->member, buffer, buffer_size, &local_offset); \
    if (rc) \
        return rc; \
\
    /* Update the size to the real value */ \
    *(UINT16 *)ptr = HOST_TO_BE_16(buffer + local_offset - ptr - 2); \
\
    if (offset != NULL) { \
        *offset = local_offset; \
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset); \
    } \
\
    return TSS2_RC_SUCCESS; \
}

#define TPM2B_UNMARSHAL_SUBTYPE(type, subtype, member) \
TSS2_RC Tss2_MU_##type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, \
                                   size_t *offset, type *dest) \
{ \
    size_t  local_offset = 0; \
    UINT16 size = 0; \
    TSS2_RC rc; \
\
    if (offset != NULL) { \
        LOG (DEBUG, "offset non-NULL, initial value: %zu", *offset); \
        local_offset = *offset; \
    } \
\
    if (buffer == NULL || (dest == NULL && offset == NULL)) { \
        LOG (WARNING, "buffer or dest and offset parameter are NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } else if (buffer_size < local_offset || \
               sizeof(size) > buffer_size - local_offset) \
    { \
        LOG (WARNING, \
             "buffer_size: %zu with offset: %zu are insufficient for object " \
             "of size %zu", \
             buffer_size, \
             local_offset, \
             sizeof(size)); \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
    if (dest && dest->size != 0) { \
        LOG (WARNING, "Size not zero"); \
        return TSS2_SYS_RC_BAD_VALUE; \
    } \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", \
         (uintptr_t)buffer, \
         (uintptr_t)dest, \
         local_offset); \
\
    rc = Tss2_MU_UINT16_Unmarshal(buffer, buffer_size, &local_offset, &size); \
    if (rc) \
        return rc; \
\
    if (size > buffer_size - local_offset) { \
        LOG (WARNING, \
             "buffer_size: %zu with offset: %zu are insufficient for object " \
             "of size %zu", \
             buffer_size, \
             local_offset, \
             (size_t)size); \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
    if (dest != NULL) { \
        dest->size = size; \
        Tss2_MU_##subtype##_Unmarshal(buffer, buffer_size, &local_offset, &dest->member); \
        if (rc) \
            return rc; \
    } else { \
        local_offset += size; \
    } \
\
    if (offset != NULL) { \
        *offset = local_offset; \
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset); \
    } \
\
    return TSS2_RC_SUCCESS; \
}

/*
 * These macros expand to (un)marshal functions for each of the TPMA types
 * the specification part 2.
 */
TPM2B_MARSHAL  (TPM2B_DIGEST);
TPM2B_UNMARSHAL(TPM2B_DIGEST);
TPM2B_MARSHAL  (TPM2B_DATA);
TPM2B_UNMARSHAL(TPM2B_DATA);
TPM2B_MARSHAL  (TPM2B_EVENT);
TPM2B_UNMARSHAL(TPM2B_EVENT);
TPM2B_MARSHAL  (TPM2B_MAX_BUFFER);
TPM2B_UNMARSHAL(TPM2B_MAX_BUFFER);
TPM2B_MARSHAL  (TPM2B_MAX_NV_BUFFER);
TPM2B_UNMARSHAL(TPM2B_MAX_NV_BUFFER);
TPM2B_MARSHAL  (TPM2B_IV);
TPM2B_UNMARSHAL(TPM2B_IV);
TPM2B_MARSHAL  (TPM2B_NAME);
TPM2B_UNMARSHAL(TPM2B_NAME);
TPM2B_MARSHAL  (TPM2B_DIGEST_VALUES);
TPM2B_UNMARSHAL(TPM2B_DIGEST_VALUES);
TPM2B_MARSHAL  (TPM2B_ATTEST);
TPM2B_UNMARSHAL(TPM2B_ATTEST);
TPM2B_MARSHAL  (TPM2B_SYM_KEY);
TPM2B_UNMARSHAL(TPM2B_SYM_KEY);
TPM2B_MARSHAL  (TPM2B_SENSITIVE_DATA);
TPM2B_UNMARSHAL(TPM2B_SENSITIVE_DATA);
TPM2B_MARSHAL  (TPM2B_PUBLIC_KEY_RSA);
TPM2B_UNMARSHAL(TPM2B_PUBLIC_KEY_RSA);
TPM2B_MARSHAL  (TPM2B_PRIVATE_KEY_RSA);
TPM2B_UNMARSHAL(TPM2B_PRIVATE_KEY_RSA);
TPM2B_MARSHAL  (TPM2B_ECC_PARAMETER);
TPM2B_UNMARSHAL(TPM2B_ECC_PARAMETER);
TPM2B_MARSHAL  (TPM2B_ENCRYPTED_SECRET);
TPM2B_UNMARSHAL(TPM2B_ENCRYPTED_SECRET);
TPM2B_MARSHAL  (TPM2B_PRIVATE_VENDOR_SPECIFIC);
TPM2B_UNMARSHAL(TPM2B_PRIVATE_VENDOR_SPECIFIC);
TPM2B_MARSHAL  (TPM2B_PRIVATE);
TPM2B_UNMARSHAL(TPM2B_PRIVATE);
TPM2B_MARSHAL  (TPM2B_ID_OBJECT);
TPM2B_UNMARSHAL(TPM2B_ID_OBJECT);
TPM2B_MARSHAL  (TPM2B_CONTEXT_SENSITIVE);
TPM2B_UNMARSHAL(TPM2B_CONTEXT_SENSITIVE);
TPM2B_MARSHAL  (TPM2B_CONTEXT_DATA);
TPM2B_UNMARSHAL(TPM2B_CONTEXT_DATA);
TPM2B_MARSHAL  (TPM2B_NONCE);
TPM2B_UNMARSHAL(TPM2B_NONCE);
TPM2B_MARSHAL  (TPM2B_TIMEOUT);
TPM2B_UNMARSHAL(TPM2B_TIMEOUT);
TPM2B_MARSHAL  (TPM2B_AUTH);
TPM2B_UNMARSHAL(TPM2B_AUTH);
TPM2B_MARSHAL  (TPM2B_OPERAND);
TPM2B_UNMARSHAL(TPM2B_OPERAND);
TPM2B_MARSHAL_SUBTYPE(TPM2B_ECC_POINT, TPMS_ECC_POINT, point);
TPM2B_UNMARSHAL_SUBTYPE(TPM2B_ECC_POINT, TPMS_ECC_POINT, point);
TPM2B_MARSHAL_SUBTYPE(TPM2B_NV_PUBLIC, TPMS_NV_PUBLIC, nvPublic);
TPM2B_UNMARSHAL_SUBTYPE(TPM2B_NV_PUBLIC, TPMS_NV_PUBLIC, nvPublic);
TPM2B_MARSHAL_SUBTYPE(TPM2B_SENSITIVE, TPMT_SENSITIVE, sensitiveArea);
TPM2B_UNMARSHAL_SUBTYPE(TPM2B_SENSITIVE, TPMT_SENSITIVE, sensitiveArea);
TPM2B_MARSHAL_SUBTYPE(TPM2B_SENSITIVE_CREATE, TPMS_SENSITIVE_CREATE, sensitive);
TPM2B_UNMARSHAL_SUBTYPE(TPM2B_SENSITIVE_CREATE, TPMS_SENSITIVE_CREATE, sensitive);
TPM2B_MARSHAL_SUBTYPE(TPM2B_CREATION_DATA, TPMS_CREATION_DATA, creationData);
TPM2B_UNMARSHAL_SUBTYPE(TPM2B_CREATION_DATA, TPMS_CREATION_DATA, creationData);
TPM2B_MARSHAL_SUBTYPE(TPM2B_PUBLIC, TPMT_PUBLIC, publicArea);
TPM2B_UNMARSHAL_SUBTYPE(TPM2B_PUBLIC, TPMT_PUBLIC, publicArea);
