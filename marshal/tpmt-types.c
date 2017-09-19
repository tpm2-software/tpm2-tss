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

#include "sapi/marshal.h"
#include "sapi/tpm20.h"
#include "tss2_endian.h"
#include "log.h"

#define ADDR &
#define VAL

#define TPMT_MARSHAL_2(type, m1, op1, fn1, m2, op2, sel, fn2) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (!src) \
        return TSS2_SYS_RC_BAD_REFERENCE; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!buffer) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)src,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, src->sel, buffer, buffer_size, &local_offset); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_UNMARSHAL_2(type, m1, fn1, m2, sel, fn2) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!dest) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(buffer, buffer_size, &local_offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, &local_offset, dest ? dest->sel : 0, dest ? &dest->m2 : NULL); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_MARSHAL_3(type, m1, op1, fn1, m2, op2, sel2, fn2, m3, op3, sel3, fn3) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (!src) \
        return TSS2_SYS_RC_BAD_REFERENCE; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!buffer) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)src,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, src->sel2, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(op3 src->m3, src->sel3, buffer, buffer_size, &local_offset); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_UNMARSHAL_3(type, m1, fn1, m2, sel2, fn2, m3, sel3, fn3) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!dest) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(buffer, buffer_size, &local_offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, &local_offset, dest ? dest->sel2 : 0, dest ? &dest->m2 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(buffer, buffer_size, &local_offset, dest ? dest->sel3 : 0, dest ? &dest->m3 : NULL); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_MARSHAL_TK(type, m1, fn1, m2, fn2, m3, fn3) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (!src) \
        return TSS2_SYS_RC_BAD_REFERENCE; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!buffer) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)src,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(src->m1, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(src->m2, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(&src->m3, buffer, buffer_size, &local_offset); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_UNMARSHAL_TK(type, m1, fn1, m2, fn2, m3, fn3) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!dest) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(buffer, buffer_size, &local_offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, &local_offset, dest ? &dest->m2 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(buffer, buffer_size, &local_offset, dest ? &dest->m3 : NULL); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_MARSHAL_4(type, m1, op1, fn1, m2, op2, fn2, m3, op3, fn3, \
                       m4, sel4, op4, fn4) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (!src) \
        return TSS2_SYS_RC_BAD_REFERENCE; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!buffer) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)src,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(op3 src->m3, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(op4 src->m4, src->sel4, buffer, buffer_size, &local_offset); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_UNMARSHAL_4(type, m1, fn1, m2, fn2, m3, fn3, m4, sel4, fn4) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!dest) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(buffer, buffer_size, &local_offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, &local_offset, dest ? &dest->m2 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(buffer, buffer_size, &local_offset, dest ? &dest->m3 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(buffer, buffer_size, &local_offset, dest ? dest->sel4 : 0, dest ? &dest->m4 : NULL); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_MARSHAL_5(type, m1, op1, fn1, m2, op2, fn2, m3, op3, fn3, \
                       m4, op4, fn4, m5, op5, fn5) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (!src) \
        return TSS2_SYS_RC_BAD_REFERENCE; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!buffer) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)src,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(op3 src->m3, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(op4 src->m4, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn5(op5 src->m5, buffer, buffer_size, &local_offset); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_UNMARSHAL_5(type, m1, fn1, m2, fn2, m3, fn3, m4, fn4, m5, fn5) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!dest) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(buffer, buffer_size, &local_offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, &local_offset, dest ? &dest->m2 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(buffer, buffer_size, &local_offset, dest ? &dest->m3 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(buffer, buffer_size, &local_offset, dest ? &dest->m4 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn5(buffer, buffer_size, &local_offset, dest ? &dest->m5 : NULL); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_MARSHAL_6(type, m1, op1, fn1, m2, op2, fn2, m3, op3, fn3, \
                       m4, op4, fn4, m5, op5, sel5, fn5, m6, op6, sel6, fn6) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (!src) \
        return TSS2_SYS_RC_BAD_REFERENCE; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!buffer) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)src,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(op3 src->m3, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(op4 src->m4, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn5(op5 src->m5, src->sel5, buffer, buffer_size, &local_offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn6(op6 src->m6, src->sel6, buffer, buffer_size, &local_offset); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

#define TPMT_UNMARSHAL_6(type, m1, fn1, m2, fn2, m3, fn3, m4, fn4, m5, sel5, fn5, m6, sel6, fn6) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
    size_t local_offset = 0; \
\
    if (offset) \
        local_offset = *offset; \
    else if (!dest) \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, local_offset); \
\
    ret = fn1(buffer, buffer_size, &local_offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, &local_offset, dest ? &dest->m2 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(buffer, buffer_size, &local_offset, dest ? &dest->m3 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(buffer, buffer_size, &local_offset, dest ? &dest->m4 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn5(buffer, buffer_size, &local_offset, dest ? dest->sel5 : 0, dest ? &dest->m5 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn6(buffer, buffer_size, &local_offset, dest ? dest->sel6 : 0, dest ? &dest->m6 : NULL); \
\
    if (offset && ret == TSS2_RC_SUCCESS) { \
        *offset = local_offset; \
    } \
\
    return ret; \
}

/*
 * These macros expand to (un)marshal functions for each of the TPMT types
 * the specification part 2.
 */
TPMT_MARSHAL_2(TPMT_HA, hashAlg, VAL, UINT16_Marshal,
               digest, ADDR, hashAlg, TPMU_HA_Marshal)

TPMT_UNMARSHAL_2(TPMT_HA, hashAlg, UINT16_Unmarshal,
                 digest, hashAlg, TPMU_HA_Unmarshal)

TPMT_MARSHAL_3(TPMT_SYM_DEF, algorithm, VAL, UINT16_Marshal,
               keyBits, ADDR, algorithm, TPMU_SYM_KEY_BITS_Marshal,
               mode, ADDR, algorithm, TPMU_SYM_MODE_Marshal)

TPMT_UNMARSHAL_3(TPMT_SYM_DEF, algorithm, UINT16_Unmarshal,
                 keyBits, algorithm, TPMU_SYM_KEY_BITS_Unmarshal,
                 mode, algorithm, TPMU_SYM_MODE_Unmarshal)

TPMT_MARSHAL_3(TPMT_SYM_DEF_OBJECT, algorithm, VAL, UINT16_Marshal,
               keyBits, ADDR, algorithm, TPMU_SYM_KEY_BITS_Marshal,
               mode, ADDR, algorithm, TPMU_SYM_MODE_Marshal)

TPMT_UNMARSHAL_3(TPMT_SYM_DEF_OBJECT, algorithm, UINT16_Unmarshal,
                 keyBits, algorithm, TPMU_SYM_KEY_BITS_Unmarshal,
                 mode, algorithm, TPMU_SYM_MODE_Unmarshal)

TPMT_MARSHAL_2(TPMT_KEYEDHASH_SCHEME, scheme, VAL, UINT16_Marshal,
               details, ADDR, scheme, TPMU_SCHEME_KEYEDHASH_Marshal)

TPMT_UNMARSHAL_2(TPMT_KEYEDHASH_SCHEME, scheme, UINT16_Unmarshal,
                 details, scheme, TPMU_SCHEME_KEYEDHASH_Unmarshal)

TPMT_MARSHAL_2(TPMT_SIG_SCHEME, scheme, VAL, UINT16_Marshal,
               details, ADDR, scheme, TPMU_SIG_SCHEME_Marshal)

TPMT_UNMARSHAL_2(TPMT_SIG_SCHEME, scheme, UINT16_Unmarshal,
                 details, scheme, TPMU_SIG_SCHEME_Unmarshal)

TPMT_MARSHAL_2(TPMT_KDF_SCHEME, scheme, VAL, UINT16_Marshal,
               details, ADDR, scheme, TPMU_KDF_SCHEME_Marshal)

TPMT_UNMARSHAL_2(TPMT_KDF_SCHEME, scheme, UINT16_Unmarshal,
                 details, scheme, TPMU_KDF_SCHEME_Unmarshal)

TPMT_MARSHAL_2(TPMT_ASYM_SCHEME, scheme, VAL, UINT16_Marshal,
               details, ADDR, scheme, TPMU_ASYM_SCHEME_Marshal)

TPMT_UNMARSHAL_2(TPMT_ASYM_SCHEME, scheme, UINT16_Unmarshal,
                 details, scheme, TPMU_ASYM_SCHEME_Unmarshal)

TPMT_MARSHAL_2(TPMT_RSA_SCHEME, scheme, VAL, UINT16_Marshal,
               details, ADDR, scheme, TPMU_ASYM_SCHEME_Marshal)

TPMT_UNMARSHAL_2(TPMT_RSA_SCHEME, scheme, UINT16_Unmarshal,
                 details, scheme, TPMU_ASYM_SCHEME_Unmarshal)

TPMT_MARSHAL_2(TPMT_RSA_DECRYPT, scheme, VAL, UINT16_Marshal,
               details, ADDR, scheme, TPMU_ASYM_SCHEME_Marshal)

TPMT_UNMARSHAL_2(TPMT_RSA_DECRYPT, scheme, UINT16_Unmarshal,
                 details, scheme, TPMU_ASYM_SCHEME_Unmarshal)

TPMT_MARSHAL_2(TPMT_ECC_SCHEME, scheme, VAL, UINT16_Marshal,
               details, ADDR, scheme, TPMU_ASYM_SCHEME_Marshal)

TPMT_UNMARSHAL_2(TPMT_ECC_SCHEME, scheme, UINT16_Unmarshal,
                 details, scheme, TPMU_ASYM_SCHEME_Unmarshal)

TPMT_MARSHAL_2(TPMT_SIGNATURE, sigAlg, VAL, UINT16_Marshal,
               signature, ADDR, sigAlg, TPMU_SIGNATURE_Marshal)

TPMT_UNMARSHAL_2(TPMT_SIGNATURE, sigAlg, UINT16_Unmarshal,
                 signature, sigAlg, TPMU_SIGNATURE_Unmarshal)

TPMT_MARSHAL_4(TPMT_SENSITIVE, sensitiveType, VAL, UINT16_Marshal,
               authValue, ADDR, TPM2B_DIGEST_Marshal,
               seedValue, ADDR, TPM2B_DIGEST_Marshal,
               sensitive, sensitiveType, ADDR, TPMU_SENSITIVE_COMPOSITE_Marshal)

TPMT_UNMARSHAL_4(TPMT_SENSITIVE, sensitiveType, UINT16_Unmarshal,
                 authValue, TPM2B_DIGEST_Unmarshal,
                 seedValue, TPM2B_DIGEST_Unmarshal,
                 sensitive, sensitiveType, TPMU_SENSITIVE_COMPOSITE_Unmarshal)

TPMT_MARSHAL_6(TPMT_PUBLIC, type, VAL, UINT16_Marshal,
               nameAlg, VAL, UINT16_Marshal,
               objectAttributes, VAL, TPMA_OBJECT_Marshal,
               authPolicy, ADDR, TPM2B_DIGEST_Marshal,
               parameters, ADDR, type, TPMU_PUBLIC_PARMS_Marshal,
               unique, ADDR, type, TPMU_PUBLIC_ID_Marshal)

TPMT_UNMARSHAL_6(TPMT_PUBLIC, type, UINT16_Unmarshal,
                 nameAlg, UINT16_Unmarshal,
                 objectAttributes, TPMA_OBJECT_Unmarshal,
                 authPolicy, TPM2B_DIGEST_Unmarshal,
                 parameters, type, TPMU_PUBLIC_PARMS_Unmarshal,
                 unique, type, TPMU_PUBLIC_ID_Unmarshal)

TPMT_MARSHAL_2(TPMT_PUBLIC_PARMS, type, VAL, UINT16_Marshal,
               parameters, ADDR, type, TPMU_PUBLIC_PARMS_Marshal)

TPMT_UNMARSHAL_2(TPMT_PUBLIC_PARMS, type, UINT16_Unmarshal,
                 parameters, type, TPMU_PUBLIC_PARMS_Unmarshal)

TPMT_MARSHAL_TK(TPMT_TK_CREATION, tag, UINT16_Marshal,
                hierarchy, UINT32_Marshal, digest, TPM2B_DIGEST_Marshal)

TPMT_UNMARSHAL_TK(TPMT_TK_CREATION, tag, UINT16_Unmarshal,
                  hierarchy, UINT32_Unmarshal, digest, TPM2B_DIGEST_Unmarshal)

TPMT_MARSHAL_TK(TPMT_TK_VERIFIED, tag, UINT16_Marshal,
                hierarchy, UINT32_Marshal, digest, TPM2B_DIGEST_Marshal)

TPMT_UNMARSHAL_TK(TPMT_TK_VERIFIED, tag, UINT16_Unmarshal,
                  hierarchy, UINT32_Unmarshal, digest, TPM2B_DIGEST_Unmarshal)

TPMT_MARSHAL_TK(TPMT_TK_AUTH, tag, UINT16_Marshal,
                hierarchy, UINT32_Marshal, digest, TPM2B_DIGEST_Marshal)

TPMT_UNMARSHAL_TK(TPMT_TK_AUTH, tag, UINT16_Unmarshal,
                  hierarchy, UINT32_Unmarshal, digest, TPM2B_DIGEST_Unmarshal)

TPMT_MARSHAL_TK(TPMT_TK_HASHCHECK, tag, UINT16_Marshal,
                hierarchy, UINT32_Marshal, digest, TPM2B_DIGEST_Marshal)

TPMT_UNMARSHAL_TK(TPMT_TK_HASHCHECK, tag, UINT16_Unmarshal,
                  hierarchy, UINT32_Unmarshal, digest, TPM2B_DIGEST_Unmarshal)
