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

#ifndef BASE_TYPES_H
#define BASE_TYPES_H

#include "sapi/tpm20.h"

/*
 * This no-op function is used in base-types.c in BASE_(UN)?MARSHAL so that
 * we have a valid function pointer for the function template.
 */
static inline UINT8 noop8 (UINT8 value) { return value; }

#define CAST_TO_TYPE(ptr, type) (*(type*)ptr)
#define CAST_TO_UINT8(ptr)      CAST_TO_TYPE(ptr, UINT8)
#define CAST_TO_UINT16(ptr)     CAST_TO_TYPE(ptr, UINT16)
#define CAST_TO_UINT32(ptr)     CAST_TO_TYPE(ptr, UINT32)

#if defined(HAVE_ENDIAN_H)

#include <endian.h>
#define HOST_TO_BE_8(value)  noop8   (value)
#define HOST_TO_BE_16(value) htobe16 (value)
#define HOST_TO_BE_32(value) htobe32 (value)
#define BE_TO_HOST_8(value)  noop8   (value)
#define BE_TO_HOST_16(value) be16toh (value)
#define BE_TO_HOST_32(value) be32toh (value)

#elif defined(WORDS_BIGENDIAN)

static inline UINT16 noop16 (UINT16 value) { return value; }
static inline UINT32 noop32 (UINT32 value) { return value; }
#define HOST_TO_BE_8(value)  noop8  (value)
#define HOST_TO_BE_16(value) noop16 (value)
#define HOST_TO_BE_32(value) noop32 (value)
#define BE_TO_HOST_8(value)  noop8  (value)
#define BE_TO_HOST_16(value) noop16 (value)
#define BE_TO_HOST_32(value) noop32 (value)

#else

UINT16 endian_conv_16 (UINT16 value);
UINT32 endian_conv_32 (UINT32 value);
#define HOST_TO_BE_8(value)  noop8          (value)
#define HOST_TO_BE_16(value) endian_conv_16 (value)
#define HOST_TO_BE_32(value) endian_conv_32 (value)
#define BE_TO_HOST_8(value)  noop8          (value)
#define BE_TO_HOST_16(value) endian_conv_16 (value)
#define BE_TO_HOST_32(value) endian_conv_32 (value)

#endif /* HAVE_ENDIAN_H */
#endif /* BASE_TYPES_H  */
