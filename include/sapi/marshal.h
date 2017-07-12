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

#ifndef MARSHAL_H
#define MARSHAL_H

#include <stdlib.h>
#include <sapi/tpm20.h>

#define TSS2_TYPES_RC_LAYER TSS2_ERROR_LEVEL(14)
#define TSS2_TYPES_RC_BAD_REFERENCE \
    ((TSS2_RC)(TSS2_TYPES_RC_LAYER | TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_TYPES_RC_INSUFFICIENT_BUFFER \
    ((TSS2_RC)(TSS2_TYPES_RC_LAYER | TSS2_BASE_RC_INSUFFICIENT_BUFFER))

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC
BYTE_Marshal (
    BYTE           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
BYTE_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    BYTE           *dest
    );

TSS2_RC
INT8_Marshal (
    INT8            src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
INT8_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    INT8           *dest
    );

TSS2_RC
INT16_Marshal (
    INT16           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
INT16_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    INT16          *dest
    );

TSS2_RC
INT32_Marshal (
    INT32           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
INT32_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    INT32          *dest
    );

TSS2_RC
INT64_Marshal (
    INT64           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
INT64_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    INT64          *dest
    );

TSS2_RC
UINT8_Marshal (
    UINT8           src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
UINT8_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT8          *dest
    );

TSS2_RC
UINT16_Marshal (
    UINT16          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
UINT16_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT16         *dest
    );

TSS2_RC
UINT32_Marshal (
    UINT32          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
UINT32_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT32         *dest
    );

TSS2_RC
UINT64_Marshal (
    UINT64          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
UINT64_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    UINT64         *dest
    );

TSS2_RC
TPM_CC_Marshal (
    TPM_CC          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
TPM_CC_Unmarshal (
    uint8_t const   buffer [],
    size_t          buffer_size,
    size_t         *offset,
    TPM_CC         *dest
    );

TSS2_RC
TPM_ST_Marshal (
    TPM_ST          src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset
    );

TSS2_RC
TPM_ST_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM_ST         *dest
    );

TSS2_RC
TPMA_ALGORITHM_Marshal (
    TPMA_ALGORITHM  src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t          *offset);

TSS2_RC
TPMA_ALGORITHM_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_ALGORITHM *dest);

TSS2_RC
TPMA_CC_Marshal (
    TPMA_CC         src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_CC_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_CC        *dest);

TSS2_RC
TPMA_LOCALITY_Marshal (
    TPMA_LOCALITY   src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_LOCALITY_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_LOCALITY  *dest);
TSS2_RC

TPMA_NV_Marshal (
    TPMA_NV         src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_NV_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_NV        *dest);

TSS2_RC
TPMA_OBJECT_Marshal (
    TPMA_OBJECT     src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_OBJECT_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_OBJECT    *dest);

TSS2_RC
TPMA_PERMANENT_Marshal (
    TPMA_PERMANENT  src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_PERMANENT_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_PERMANENT *dest);

TSS2_RC
TPMA_SESSION_Marshal (
    TPMA_SESSION    src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_SESSION_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_SESSION   *dest);

TSS2_RC
TPMA_STARTUP_CLEAR_Marshal (
    TPMA_STARTUP_CLEAR src,
    uint8_t         buffer [],
    size_t          buffer_size,
    size_t         *offset);

TSS2_RC
TPMA_STARTUP_CLEAR_Unmarshal (
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPMA_STARTUP_CLEAR *dest);

#ifdef __cplusplus
}
#endif

#endif /* MARSHAL_H */
