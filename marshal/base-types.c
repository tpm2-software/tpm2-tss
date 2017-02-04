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

#include "sapi/marshal.h"
#include "sapi/tpm20.h"

#include "base-types.h"

#define BASE_MARSHAL(type, marshal_func) \
TSS2_RC \
type##_Marshal ( \
    type    const *src, \
    uint8_t        buffer [], \
    size_t         buffer_size, \
    size_t        *offset \
    ) \
{ \
    size_t  local_offset = 0; \
\
    if (offset != NULL) \
        local_offset = *offset; \
\
    if (src == NULL || (buffer == NULL && offset == NULL)) { \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } else if (buffer == NULL && offset != NULL) { \
        *offset += sizeof (*src); \
        return TSS2_RC_SUCCESS; \
    } else if (buffer_size < local_offset || \
               buffer_size - local_offset < sizeof (*src)) \
    { \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
\
    data_ptr  = (type*)&buffer [local_offset]; \
    *data_ptr = marshal_func (*src); \
    if (offset != NULL) { \
        *offset = local_offset + sizeof (*src); \
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
    if (offset != NULL) \
        local_offset = *offset; \
\
    if (buffer == NULL || (dest == NULL && offset == NULL)) { \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } else if (dest == NULL && offset != NULL) { \
        *offset += sizeof (type); \
        return TSS2_RC_SUCCESS; \
    } else if (buffer_size < local_offset || \
               sizeof (*dest) > buffer_size - local_offset) \
    { \
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER; \
    } \
\
    data_ptr = (type*)&buffer [local_offset]; \
    *dest = unmarshal_func (*data_ptr); \
    if (offset != NULL) { \
        *offset = local_offset + sizeof (*dest); \
    } \
\
    return TSS2_RC_SUCCESS; \
}

BASE_MARSHAL   (UINT8,  HOST_TO_BE_8);
BASE_UNMARSHAL (UINT8,  BE_TO_HOST_8);
BASE_MARSHAL   (UINT16, HOST_TO_BE_16);
BASE_UNMARSHAL (UINT16, BE_TO_HOST_16);
