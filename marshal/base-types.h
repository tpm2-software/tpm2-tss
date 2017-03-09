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
 * These no-op functions are used on big endian (BE) systems for the host
 * to / from BE macros. We need them so that we have a valid function
 * pointers for the base type marshalling function template.
 */
static inline UINT8  noop_8  (UINT8 value)  { return value; };
static inline UINT16 noop_16 (UINT16 value) { return value; };
static inline UINT32 noop_32 (UINT32 value) { return value; };
static inline UINT64 noop_64 (UINT64 value) { return value; };
/*
 * These functions are used to convert the endianness of base types. We
 * use them on little endian (LE) systems for the host to / from BE macros.
 */
UINT8  endian_conv_8  (UINT8 value);
UINT16 endian_conv_16 (UINT16 value);
UINT32 endian_conv_32 (UINT32 value);
UINT64 endian_conv_64 (UINT64 value);
/*
 * These macros should be used in any place where a base type needs to be
 * converted from the host byte order (host) to a big endian representation.
 */
#if defined(WORDS_BIGENDIAN)
#define HOST_TO_BE_8(value)  noop_8  (value)
#define HOST_TO_BE_16(value) noop_16 (value)
#define HOST_TO_BE_32(value) noop_32 (value)
#define HOST_TO_BE_64(value) noop_64 (value)
#define BE_TO_HOST_8(value)  noop_8  (value)
#define BE_TO_HOST_16(value) noop_16 (value)
#define BE_TO_HOST_32(value) noop_32 (value)
#define BE_TO_HOST_64(value) noop_64 (value)
#else
#define HOST_TO_BE_8(value)  endian_conv_8  (value)
#define HOST_TO_BE_16(value) endian_conv_16 (value)
#define HOST_TO_BE_32(value) endian_conv_32 (value)
#define HOST_TO_BE_64(value) endian_conv_64 (value)
#define BE_TO_HOST_8(value)  endian_conv_8  (value)
#define BE_TO_HOST_16(value) endian_conv_16 (value)
#define BE_TO_HOST_32(value) endian_conv_32 (value)
#define BE_TO_HOST_64(value) endian_conv_64 (value)
#endif /* WORDS_BIGENDIAN */
#endif /* BASE_TYPES_H  */
