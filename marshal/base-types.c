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

#include "sapi/tpm20.h"

TSS2_RC
UINT8_Marshal (
    UINT8 const  *src,
    uint8_t       buffer [],
    size_t        buffer_size,
    size_t       *offset
    )
{
    size_t local_offset = 0;

    if (offset != NULL)
        local_offset = *offset;

    if (src == NULL || (buffer == NULL && offset == NULL)) {
        return TSS2_TYPES_RC_BAD_REFERENCE;
    } else if (buffer == NULL && offset != NULL) {
        *offset += sizeof (*src);
        return TSS2_RC_SUCCESS;
    } else if (buffer_size < local_offset ||
               buffer_size - local_offset < sizeof (*src))
    {
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER;
    }
    buffer [local_offset] = *src;
    if (offset != NULL) {
        *offset = local_offset + sizeof (*src);
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
UINT8_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT8          *dest
    )
{
    size_t local_offset = 0;

    if (offset != NULL)
        local_offset = *offset;

    if (buffer == NULL || (dest == NULL && offset == NULL)) {
        return TSS2_TYPES_RC_BAD_REFERENCE;
    } else if (dest == NULL && offset != NULL) {
        *offset += sizeof (UINT8);
        return TSS2_RC_SUCCESS;
    } else if (buffer_size < local_offset ||
               sizeof (*dest) > buffer_size - local_offset)
    {
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER;
    }

    *dest = buffer [local_offset];
    if (offset != NULL) {
        *offset = local_offset + sizeof (*dest);
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
UINT16_Marshal (
    UINT16 const *src,
    uint8_t       buffer [],
    size_t        buffer_size,
    size_t       *offset
    )
{
    size_t local_offset = 0;

    if (offset != NULL)
        local_offset = *offset;

    if (src == NULL || (buffer == NULL && offset == NULL)) {
        return TSS2_TYPES_RC_BAD_REFERENCE;
    } else if (buffer == NULL && offset != NULL) {
        *offset += sizeof (*src);
        return TSS2_RC_SUCCESS;
    } else if (buffer_size < local_offset ||
               buffer_size - local_offset < sizeof (*src))
    {
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER;
    }
    (*(UINT16*)&buffer [local_offset]) = htobe16 (*src);
    if (offset != NULL) {
        *offset = local_offset + sizeof (*src);
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
UINT16_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT16         *dest
    )
{
    size_t local_offset = 0;

    if (offset != NULL)
        local_offset = *offset;

    if (buffer == NULL || (dest == NULL && offset == NULL)) {
        return TSS2_TYPES_RC_BAD_REFERENCE;
    } else if (dest == NULL && offset != NULL) {
        *offset += sizeof (UINT16);
        return TSS2_RC_SUCCESS;
    } else if (buffer_size < local_offset ||
               sizeof (*dest) > buffer_size - local_offset)
    {
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER;
    }

    *dest = be16toh (*(UINT16*)&buffer [local_offset]);
    if (offset != NULL) {
        *offset = local_offset + sizeof (*dest);
    }

    return TSS2_RC_SUCCESS;
}
