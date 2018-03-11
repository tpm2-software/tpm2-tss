/***********************************************************************;
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

#ifndef TSS2_ENDIAN_H
#define TSS2_ENDIAN_H

#if defined(__linux__) || defined(__unix__)
#include <endian.h>

#define HOST_TO_BE_16(value) htobe16(value)
#define HOST_TO_BE_32(value) htobe32(value)
#define HOST_TO_BE_64(value) htobe64(value)
#define BE_TO_HOST_16(value) be16toh(value)
#define BE_TO_HOST_32(value) be32toh(value)
#define BE_TO_HOST_64(value) be64toh(value)

#else /* linux || unix */

#if defined(WORDS_BIGENDIAN)

#define HOST_TO_BE_16(value) (value)
#define HOST_TO_BE_32(value) (value)
#define HOST_TO_BE_64(value) (value)
#define BE_TO_HOST_16(value) (value)
#define BE_TO_HOST_32(value) (value)
#define BE_TO_HOST_64(value) (value)

#else
#include <stdint.h>

static inline uint16_t endian_conv_16(uint16_t value)
{
    return ((value & (0xff))      << 8) | \
           ((value & (0xff << 8)) >> 8);
}

static inline uint32_t endian_conv_32(uint32_t value)
{
    return ((value & (0xff))       << 24) | \
           ((value & (0xff << 8))  << 8)  | \
           ((value & (0xff << 16)) >> 8)  | \
           ((value & (0xff << 24)) >> 24);
}

static inline uint64_t endian_conv_64(uint64_t value)
{
    return ((value & (0xffULL))       << 56) | \
           ((value & (0xffULL << 8))  << 40) | \
           ((value & (0xffULL << 16)) << 24) | \
           ((value & (0xffULL << 24)) << 8)  | \
           ((value & (0xffULL << 32)) >> 8)  | \
           ((value & (0xffULL << 40)) >> 24) | \
           ((value & (0xffULL << 48)) >> 40) | \
           ((value & (0xffULL << 56)) >> 56);
}

#define HOST_TO_BE_16(value) endian_conv_16(value)
#define HOST_TO_BE_32(value) endian_conv_32(value)
#define HOST_TO_BE_64(value) endian_conv_64(value)
#define BE_TO_HOST_16(value) endian_conv_16(value)
#define BE_TO_HOST_32(value) endian_conv_32(value)
#define BE_TO_HOST_64(value) endian_conv_64(value)

#endif /* WORDS_BIGENDIAN */
#endif /* linux || unix */
#endif /* TSS2_ENDIAN_H */
