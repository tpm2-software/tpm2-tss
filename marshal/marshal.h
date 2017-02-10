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
UINT8_Marshal (
    UINT8 const    *src,
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

#ifdef __cplusplus
}
#endif

#endif /* MARSHAL_H */
