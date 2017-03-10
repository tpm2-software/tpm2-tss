//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <inttypes.h>
#include <string.h>

#include "sapi/marshal.h"
#include "sapi/tpm20.h"

#include "log.h"
#include "base-types.h"

#define BASE_MARSHAL(type, marshal_func) \
TSS2_RC \
type##_Marshal ( \
    type           src, \
    uint8_t        buffer [], \
    size_t         buffer_size, \
    size_t        *offset \
    ) \
{ \
    size_t  local_offset = 0; \
\
    if (offset != NULL) { \
        LOG (INFO, "offset non-NULL, initial value: %zu", *offset); \
        local_offset = *offset; \
    } \
\
    if (buffer == NULL && offset == NULL) { \
        LOG (WARNING, "buffer and offset parameter are NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } else if (buffer == NULL && offset != NULL) { \
        *offset += sizeof (src); \
        LOG (INFO, "buffer NULL and offset non-NULL, updating offset to %zu", \
             *offset); \
        return TSS2_RC_SUCCESS; \
    } else if (buffer_size < local_offset || \
               buffer_size - local_offset < sizeof (src)) \
    { \
        LOG (WARNING, \
             "buffer_size: %zu with offset: %zu are insufficient for object " \
             "of size %zu", \
             buffer_size, \
             local_offset, \
             sizeof (src)); \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", \
         (uintptr_t)&src, \
         (uintptr_t)buffer, \
         local_offset); \
    src = marshal_func (src); \
    memcpy (&buffer [local_offset], &src, sizeof (src)); \
    if (offset != NULL) { \
        *offset = local_offset + sizeof (src); \
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset); \
    } \
\
    return TSS2_RC_SUCCESS; \
}

#define BASE_UNMARSHAL(type, unmarshal_func) \
TSS2_RC \
type##_Unmarshal ( \
    uint8_t const buffer[], \
    size_t        buffer_size, \
    size_t       *offset, \
    type         *dest \
    ) \
{ \
    size_t  local_offset = 0; \
\
    if (offset != NULL) { \
        LOG (INFO, "offset non-NULL, initial value: %zu", *offset); \
        local_offset = *offset; \
    } \
\
    if (buffer == NULL || (dest == NULL && offset == NULL)) { \
        LOG (WARNING, "buffer or dest and offset parameter are NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } else if (dest == NULL && offset != NULL) { \
        *offset += sizeof (type); \
        LOG (INFO, \
             "buffer NULL and offset non-NULL, updating offset to %zu", \
             *offset); \
        return TSS2_RC_SUCCESS; \
    } else if (buffer_size < local_offset || \
               sizeof (*dest) > buffer_size - local_offset) \
    { \
        LOG (WARNING, \
             "buffer_size: %zu with offset: %zu are insufficient for object " \
             "of size %zu", \
             buffer_size, \
             local_offset, \
             sizeof (*dest)); \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", \
         (uintptr_t)buffer, \
         (uintptr_t)dest, \
         local_offset); \
    type tmp = 0; \
    memcpy (&tmp, &buffer [local_offset], sizeof (tmp)); \
    *dest = unmarshal_func (tmp); \
    if (offset != NULL) { \
        *offset = local_offset + sizeof (*dest); \
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset); \
    } \
\
    return TSS2_RC_SUCCESS; \
}

/*
 * These macros expand to (un)marshal functions for each of the base types
 * the specification part 2, table 3: Definition of Base Types.
 */
BASE_MARSHAL   (BYTE,   HOST_TO_BE_8);
BASE_UNMARSHAL (BYTE,   BE_TO_HOST_8);
BASE_MARSHAL   (INT8,   HOST_TO_BE_8);
BASE_UNMARSHAL (INT8,   BE_TO_HOST_8);
BASE_MARSHAL   (INT16,  HOST_TO_BE_16);
BASE_UNMARSHAL (INT16,  BE_TO_HOST_16);
BASE_MARSHAL   (INT32,  HOST_TO_BE_32);
BASE_UNMARSHAL (INT32,  BE_TO_HOST_32);
BASE_MARSHAL   (INT64,  HOST_TO_BE_64);
BASE_UNMARSHAL (INT64,  BE_TO_HOST_64);
BASE_MARSHAL   (UINT8,  HOST_TO_BE_8);
BASE_UNMARSHAL (UINT8,  BE_TO_HOST_8);
BASE_MARSHAL   (UINT16, HOST_TO_BE_16);
BASE_UNMARSHAL (UINT16, BE_TO_HOST_16);
BASE_MARSHAL   (UINT32, HOST_TO_BE_32);
BASE_UNMARSHAL (UINT32, BE_TO_HOST_32);
BASE_MARSHAL   (UINT64, HOST_TO_BE_64);
BASE_UNMARSHAL (UINT64, BE_TO_HOST_64);

UINT8
endian_conv_8 (UINT8 value)
{
    return value;
}
UINT16
endian_conv_16 (UINT16 value)
{
    return ((value & (0xff))      << 8) | \
           ((value & (0xff << 8)) >> 8);
}
UINT32
endian_conv_32 (UINT32 value)
{
    return ((value & (0xff))       << 24) | \
           ((value & (0xff << 8))  << 8)  | \
           ((value & (0xff << 16)) >> 8)  | \
           ((value & (0xff << 24)) >> 24);
}
UINT64
endian_conv_64 (UINT64 value)
{
    return ((value & (0xffL))       << 56) | \
           ((value & (0xffL << 8))  << 40) | \
           ((value & (0xffL << 16)) << 24) | \
           ((value & (0xffL << 24)) << 8)  | \
           ((value & (0xffL << 32)) >> 8)  | \
           ((value & (0xffL << 40)) >> 24) | \
           ((value & (0xffL << 48)) >> 40) | \
           ((value & (0xffL << 56)) >> 56);
}
TSS2_RC
TPM_CC_Marshal (
    TPM_CC          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    )
{
    LOG (DEBUG, "Marshalling TPM_CC as UINT32");
    return UINT32_Marshal (src, buffer, buffer_size, offset);
}
TSS2_RC
TPM_CC_Unmarshal (
    uint8_t const   buffer [],
    size_t          buffer_size,
    size_t         *offset,
    TPM_CC         *dest
    )
{
    LOG (DEBUG, "Unmarshalling TPM_CC as UINT32");
    return UINT32_Unmarshal (buffer, buffer_size, offset, dest);
}
TSS2_RC
TPM_ST_Marshal (
    TPM_ST          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    )
{
    LOG (DEBUG, "Marshalling TPM_ST as UINT16");
    return UINT16_Marshal ((UINT16)src, buffer, buffer_size, offset);
}
TSS2_RC
TPM_ST_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM_ST         *dest
    )
{
    LOG (DEBUG, "Unmarshalling TPM_ST as UINT16");
    return UINT16_Unmarshal (buffer, buffer_size, offset, (UINT16*)dest);
}
