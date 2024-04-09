/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#ifndef TSS2_ENDIAN_H
#define TSS2_ENDIAN_H

#if defined(__linux__) || defined(__unix__)
#if defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#define HOST_TO_BE_16(value) htobe16(value)
#define HOST_TO_BE_32(value) htobe32(value)
#define HOST_TO_BE_64(value) htobe64(value)
#define BE_TO_HOST_16(value) be16toh(value)
#define BE_TO_HOST_32(value) be32toh(value)
#define BE_TO_HOST_64(value) be64toh(value)

#define HOST_TO_LE_16(value) htole16(value)
#define HOST_TO_LE_32(value) htole32(value)
#define HOST_TO_LE_64(value) htole64(value)
#define LE_TO_HOST_16(value) le16toh(value)
#define LE_TO_HOST_32(value) le32toh(value)
#define LE_TO_HOST_64(value) le64toh(value)

#else /* linux || unix */

#include <stdint.h>

static inline uint16_t endian_conv_16(uint16_t value)
{
    return ((value & (((uint16_t)0xffU)))      << 8) | \
           ((value & (((uint16_t)0xffU) << 8)) >> 8);
}

static inline uint32_t endian_conv_32(uint32_t value)
{
    return ((value & (((uint32_t)0xffU)))       << 24) | \
           ((value & (((uint32_t)0xffU) << 8))  << 8)  | \
           ((value & (((uint32_t)0xffU) << 16)) >> 8)  | \
           ((value & (((uint32_t)0xffU) << 24)) >> 24);
}

static inline uint64_t endian_conv_64(uint64_t value)
{
    return ((value & (((uint64_t)0xffU)))       << 56) | \
           ((value & (((uint64_t)0xffU) << 8))  << 40) | \
           ((value & (((uint64_t)0xffU) << 16)) << 24) | \
           ((value & (((uint64_t)0xffU) << 24)) << 8)  | \
           ((value & (((uint64_t)0xffU) << 32)) >> 8)  | \
           ((value & (((uint64_t)0xffU) << 40)) >> 24) | \
           ((value & (((uint64_t)0xffU) << 48)) >> 40) | \
           ((value & (((uint64_t)0xffU) << 56)) >> 56);
}

#if defined(WORDS_BIGENDIAN)

#define HOST_TO_BE_16(value) (value)
#define HOST_TO_BE_32(value) (value)
#define HOST_TO_BE_64(value) (value)
#define BE_TO_HOST_16(value) (value)
#define BE_TO_HOST_32(value) (value)
#define BE_TO_HOST_64(value) (value)

#define HOST_TO_LE_16(value) endian_conv_16(value)
#define HOST_TO_LE_32(value) endian_conv_32(value)
#define HOST_TO_LE_64(value) endian_conv_64(value)
#define LE_TO_HOST_16(value) endian_conv_16(value)
#define LE_TO_HOST_32(value) endian_conv_32(value)
#define LE_TO_HOST_64(value) endian_conv_64(value)

#else /* WORDS_BIGENDIAN */

#define HOST_TO_BE_16(value) endian_conv_16(value)
#define HOST_TO_BE_32(value) endian_conv_32(value)
#define HOST_TO_BE_64(value) endian_conv_64(value)
#define BE_TO_HOST_16(value) endian_conv_16(value)
#define BE_TO_HOST_32(value) endian_conv_32(value)
#define BE_TO_HOST_64(value) endian_conv_64(value)

#define HOST_TO_LE_16(value) (value)
#define HOST_TO_LE_32(value) (value)
#define HOST_TO_LE_64(value) (value)
#define LE_TO_HOST_16(value) (value)
#define LE_TO_HOST_32(value) (value)
#define LE_TO_HOST_64(value) (value)

#endif /* WORDS_BIGENDIAN else */
#endif /* linux || unix */
#endif /* TSS2_ENDIAN_H */
