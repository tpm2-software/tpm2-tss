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

static TSS2_RC marshal_pcr_select(const UINT8 *ptr, uint8_t buffer[],
                                  size_t buffer_size, size_t *offset)
{
    TPMS_PCR_SELECT *pcrSelect = (TPMS_PCR_SELECT *)ptr;
    UINT32 i;
    TSS2_RC ret;

    if (ptr == NULL) {
        LOG (WARNING, "src param is NULL");
        return TSS2_TYPES_RC_BAD_REFERENCE;
    }

	ret = UINT8_Marshal(pcrSelect->sizeofSelect, buffer, buffer_size, offset);
    if (ret) {
        return ret;
    }

	for (i = 0; i < pcrSelect->sizeofSelect; i++)
    {
	    ret = UINT8_Marshal(pcrSelect->pcrSelect[i], buffer, buffer_size, offset);

        if (ret) {
            return ret;
        }
	}

    return TSS2_RC_SUCCESS;
}

static TSS2_RC unmarshal_pcr_select(uint8_t const buffer[], size_t buffer_size,
                                    size_t *offset, UINT8 *ptr)
{
    TPMS_PCR_SELECT *pcrSelect = (TPMS_PCR_SELECT *)ptr;
    UINT32 i;
    TSS2_RC ret;

	ret = UINT8_Unmarshal(buffer, buffer_size, offset, &pcrSelect->sizeofSelect);
    if (ret) {
        return ret;
    }

	for (i = 0; i < pcrSelect->sizeofSelect; i++)
    {
	    ret = UINT8_Unmarshal(buffer, buffer_size, offset, &pcrSelect->pcrSelect[i]);

        if (ret) {
            return ret;
        }
	}

    return TSS2_RC_SUCCESS;
}

static TSS2_RC marshal_pcr_selection(const TPMI_ALG_HASH *ptr, uint8_t buffer[],
                                     size_t buffer_size, size_t *offset)
{
    TPMS_PCR_SELECTION *pcrSelection = (TPMS_PCR_SELECTION *)ptr;
    UINT32 i;
    TSS2_RC ret;

    if (ptr == NULL) {
        LOG (WARNING, "src param is NULL");
        return TSS2_TYPES_RC_BAD_REFERENCE;
    }

	ret = UINT16_Marshal(pcrSelection->hash, buffer, buffer_size, offset);
    if (ret) {
        return ret;
    }

	ret = UINT8_Marshal(pcrSelection->sizeofSelect, buffer, buffer_size, offset);
    if (ret) {
        return ret;
    }

	for (i = 0; i < pcrSelection->sizeofSelect; i++)
    {
	    ret = UINT8_Marshal(pcrSelection->pcrSelect[i], buffer, buffer_size, offset);

        if (ret) {
            return ret;
        }
	}

    return TSS2_RC_SUCCESS;
}

static TSS2_RC unmarshal_pcr_selection(uint8_t const buffer[], size_t buffer_size,
                                       size_t *offset, TPMI_ALG_HASH *ptr)
{
    TPMS_PCR_SELECTION *pcrSelection = (TPMS_PCR_SELECTION *)ptr;
    UINT32 i;
    TSS2_RC ret;

	ret = UINT16_Unmarshal(buffer, buffer_size, offset, &pcrSelection->hash);
    if (ret) {
        return ret;
    }

	ret = UINT8_Unmarshal(buffer, buffer_size, offset, &pcrSelection->sizeofSelect);
    if (ret) {
        return ret;
    }

	for (i = 0; i < pcrSelection->sizeofSelect; i++)
    {
	    ret = UINT8_Unmarshal(buffer, buffer_size, offset, &pcrSelection->pcrSelect[i]);

        if (ret) {
            return ret;
        }
	}

    return TSS2_RC_SUCCESS;
}


static TSS2_RC marshal_tagged_pcr_selection(const TPM_PT_PCR *ptr, uint8_t buffer[],
                                            size_t buffer_size, size_t *offset)
{
    TPMS_TAGGED_PCR_SELECT *taggedPcrSelect = (TPMS_TAGGED_PCR_SELECT *)ptr;
    UINT32 i;
    TSS2_RC ret;

    if (ptr == NULL) {
        LOG (WARNING, "src param is NULL");
        return TSS2_TYPES_RC_BAD_REFERENCE;
    }

	ret = UINT32_Marshal(taggedPcrSelect->tag, buffer, buffer_size, offset);
    if (ret) {
        return ret;
    }
	ret = UINT8_Marshal(taggedPcrSelect->sizeofSelect, buffer, buffer_size, offset);
    if (ret) {
        return ret;
    }

	for (i = 0; i < taggedPcrSelect->sizeofSelect; i++)
    {
        ret = UINT8_Marshal(taggedPcrSelect->pcrSelect[i], buffer, buffer_size, offset);
        if (ret) {
            return ret;
        }
	}

    return TSS2_RC_SUCCESS;
}

static TSS2_RC unmarshal_tagged_pcr_selection(uint8_t const buffer[], size_t buffer_size,
                                              size_t *offset, TPM_PT_PCR *ptr)
{
    TPMS_TAGGED_PCR_SELECT *taggedPcrSelect = (TPMS_TAGGED_PCR_SELECT *)ptr;
    UINT32 i;
    TSS2_RC ret;

	ret = UINT32_Unmarshal(buffer, buffer_size, offset, &taggedPcrSelect->tag);
    if (ret) {
        return ret;
    }
	ret = UINT8_Unmarshal(buffer, buffer_size, offset, &taggedPcrSelect->sizeofSelect);
    if (ret) {
        return ret;
    }

	for (i = 0; i < taggedPcrSelect->sizeofSelect; i++)
    {
        ret = UINT8_Unmarshal(buffer, buffer_size, offset, &taggedPcrSelect->pcrSelect[i]);
        if (ret) {
            return ret;
        }
	}

    return TSS2_RC_SUCCESS;
}

#define TPMS_MARSHAL_1(type, m, op, fn) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)&src,  (uintptr_t)buffer, *offset); \
\
    return fn(op src->m, buffer, buffer_size, offset); \
}

#define TPMS_UNMARSHAL_1(type, m, fn) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, *offset); \
\
    return fn(buffer, buffer_size, offset, &dest->m); \
}

#define TPMS_MARSHAL_2(type, m1, op1, fn1, m2, op2, fn2) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)&src,  (uintptr_t)buffer, *offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, buffer, buffer_size, offset); \
\
    return ret; \
}

#define TPMS_UNMARSHAL_2(type, m1, fn1, m2, fn2) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, *offset); \
\
    ret = fn1(buffer, buffer_size, offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, offset, dest ? &dest->m2 : NULL); \
\
    return ret; \
}

#define TPMS_MARSHAL_3(type, m1, op1, fn1, m2, op2, fn2, m3, op3, fn3) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)&src,  (uintptr_t)buffer, *offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(op3 src->m3, buffer, buffer_size, offset); \
\
    return ret; \
}

#define TPMS_UNMARSHAL_3(type, m1, fn1, m2, fn2, m3, fn3) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, *offset); \
\
    ret = fn1(buffer, buffer_size, offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, offset, dest ? &dest->m2 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(buffer, buffer_size, offset, dest ? &dest->m3 : NULL); \
\
    return ret; \
}

#define TPMS_MARSHAL_4(type, m1, op1, fn1, m2, op2, fn2, m3, op3, fn3, m4, op4, fn4) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)&src,  (uintptr_t)buffer, *offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(op3 src->m3, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(op4 src->m4, buffer, buffer_size, offset); \
\
    return ret; \
}

#define TPMS_UNMARSHAL_4(type, m1, fn1, m2, fn2, m3, fn3, m4, fn4) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, *offset); \
\
    ret = fn1(buffer, buffer_size, offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, offset, dest ? &dest->m2 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(buffer, buffer_size, offset, dest ? &dest->m3 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(buffer, buffer_size, offset, dest ? &dest->m4 : NULL); \
\
    return ret; \
}
#define TPMS_MARSHAL_5(type, m1, op1, fn1, m2, op2, fn2, m3, op3, fn3, \
                       m4, op4, fn4, m5, op5, fn5) \
TSS2_RC type##_Marshal(type const *src, uint8_t buffer[], \
                       size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } \
\
    LOG (DEBUG, \
         "Marshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)&src,  (uintptr_t)buffer, *offset); \
\
    ret = fn1(op1 src->m1, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(op2 src->m2, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(op3 src->m3, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(op4 src->m4, buffer, buffer_size, offset); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn5(op5 src->m5, buffer, buffer_size, offset); \
\
    return ret; \
}

#define TPMS_UNMARSHAL_5(type, m1, fn1, m2, fn2, m3, fn3, m4, fn4, m5, fn5) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    LOG (DEBUG, \
         "Unmarshalling " #type " from 0x%" PRIxPTR " to buffer 0x%" PRIxPTR \
         " at index 0x%zx", (uintptr_t)dest,  (uintptr_t)buffer, *offset); \
\
    ret = fn1(buffer, buffer_size, offset, dest ? &dest->m1 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn2(buffer, buffer_size, offset, dest ? &dest->m2 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn3(buffer, buffer_size, offset, dest ? &dest->m3 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn4(buffer, buffer_size, offset, dest ? &dest->m4 : NULL); \
    if (ret != TSS2_RC_SUCCESS) \
        return ret; \
\
    ret = fn5(buffer, buffer_size, offset, dest ? &dest->m5 : NULL); \
\
    return ret; \
}

/*
 * These macros expand to (un)marshal functions for each of the TPMS types
 * the specification part 2.
 */
TPMS_MARSHAL_2(TPMS_ALG_PROPERTY,
               alg, VAL, UINT16_Marshal,
               algProperties, VAL, TPMA_ALGORITHM_Marshal)

TPMS_UNMARSHAL_2(TPMS_ALG_PROPERTY,
                 alg, UINT16_Unmarshal,
                 algProperties, TPMA_ALGORITHM_Unmarshal)

TPMS_MARSHAL_2(TPMS_ALGORITHM_DESCRIPTION,
               alg, VAL, UINT16_Marshal,
               attributes, VAL, TPMA_ALGORITHM_Marshal)

TPMS_UNMARSHAL_2(TPMS_ALGORITHM_DESCRIPTION,
                 alg, UINT16_Unmarshal,
                 attributes, TPMA_ALGORITHM_Unmarshal)

TPMS_MARSHAL_2(TPMS_TAGGED_PROPERTY,
               property, VAL, UINT32_Marshal,
               value, VAL, UINT32_Marshal)

TPMS_UNMARSHAL_2(TPMS_TAGGED_PROPERTY,
                 property, UINT32_Unmarshal,
                 value, UINT32_Unmarshal)

TPMS_MARSHAL_4(TPMS_CLOCK_INFO,
               clock, VAL, UINT64_Marshal,
               resetCount, VAL, UINT32_Marshal,
               restartCount, VAL, UINT32_Marshal,
               safe, VAL, UINT8_Marshal)

TPMS_UNMARSHAL_4(TPMS_CLOCK_INFO,
                 clock, UINT64_Unmarshal,
                 resetCount, UINT32_Unmarshal,
                 restartCount, UINT32_Unmarshal,
                 safe, UINT8_Unmarshal)

TPMS_MARSHAL_2(TPMS_TIME_INFO,
               time, VAL, UINT64_Marshal,
               clockInfo, ADDR, TPMS_CLOCK_INFO_Marshal)

TPMS_UNMARSHAL_2(TPMS_TIME_INFO,
                 time, UINT64_Unmarshal,
                 clockInfo, TPMS_CLOCK_INFO_Unmarshal)

TPMS_MARSHAL_2(TPMS_TIME_ATTEST_INFO,
               time, ADDR, TPMS_TIME_INFO_Marshal,
               firmwareVersion, VAL, UINT64_Marshal)

TPMS_UNMARSHAL_2(TPMS_TIME_ATTEST_INFO,
                 time, TPMS_TIME_INFO_Unmarshal,
                 firmwareVersion, UINT64_Unmarshal)

TPMS_MARSHAL_2(TPMS_CERTIFY_INFO,
               name, ADDR, TPM2B_NAME_Marshal,
               qualifiedName, ADDR, TPM2B_NAME_Marshal)

TPMS_UNMARSHAL_2(TPMS_CERTIFY_INFO,
                 name, TPM2B_NAME_Unmarshal,
                 qualifiedName, TPM2B_NAME_Unmarshal)

TPMS_MARSHAL_4(TPMS_COMMAND_AUDIT_INFO,
               auditCounter, VAL, UINT64_Marshal,
               digestAlg, VAL, UINT16_Marshal,
               auditDigest, ADDR, TPM2B_DIGEST_Marshal,
               commandDigest, ADDR, TPM2B_DIGEST_Marshal)

TPMS_UNMARSHAL_4(TPMS_COMMAND_AUDIT_INFO,
                 auditCounter, UINT64_Unmarshal,
                 digestAlg, UINT16_Unmarshal,
                 auditDigest, TPM2B_DIGEST_Unmarshal,
                 commandDigest, TPM2B_DIGEST_Unmarshal)

TPMS_MARSHAL_2(TPMS_SESSION_AUDIT_INFO,
               exclusiveSession, VAL, UINT8_Marshal,
               sessionDigest, ADDR, TPM2B_DIGEST_Marshal)

TPMS_UNMARSHAL_2(TPMS_SESSION_AUDIT_INFO,
                 exclusiveSession, UINT8_Unmarshal,
                 sessionDigest, TPM2B_DIGEST_Unmarshal)

TPMS_MARSHAL_2(TPMS_CREATION_INFO,
               objectName, ADDR, TPM2B_NAME_Marshal,
               creationHash, ADDR, TPM2B_DIGEST_Marshal)

TPMS_UNMARSHAL_2(TPMS_CREATION_INFO,
                 objectName, TPM2B_NAME_Unmarshal,
                 creationHash, TPM2B_DIGEST_Unmarshal)

TPMS_MARSHAL_3(TPMS_NV_CERTIFY_INFO,
               indexName, ADDR, TPM2B_NAME_Marshal,
               offset, VAL, UINT16_Marshal,
               nvContents, ADDR, TPM2B_MAX_NV_BUFFER_Marshal)

TPMS_UNMARSHAL_3(TPMS_NV_CERTIFY_INFO,
                 indexName, TPM2B_NAME_Unmarshal,
                 offset, UINT16_Unmarshal,
                 nvContents, TPM2B_MAX_NV_BUFFER_Unmarshal)

TPMS_MARSHAL_4(TPMS_AUTH_COMMAND,
               sessionHandle, VAL, UINT32_Marshal,
               nonce, ADDR, TPM2B_DIGEST_Marshal,
               sessionAttributes, VAL, TPMA_SESSION_Marshal,
               hmac, ADDR, TPM2B_DIGEST_Marshal)

TPMS_UNMARSHAL_4(TPMS_AUTH_COMMAND,
                 sessionHandle, UINT32_Unmarshal,
                 nonce, TPM2B_DIGEST_Unmarshal,
                 sessionAttributes, TPMA_SESSION_Unmarshal,
                 hmac, TPM2B_DIGEST_Unmarshal)

TPMS_MARSHAL_3(TPMS_AUTH_RESPONSE,
               nonce, ADDR, TPM2B_DIGEST_Marshal,
               sessionAttributes, VAL, TPMA_SESSION_Marshal,
               hmac, ADDR, TPM2B_DIGEST_Marshal)

TPMS_UNMARSHAL_3(TPMS_AUTH_RESPONSE,
                 nonce, TPM2B_DIGEST_Unmarshal,
                 sessionAttributes, TPMA_SESSION_Unmarshal,
                 hmac, TPM2B_DIGEST_Unmarshal)

TPMS_MARSHAL_2(TPMS_SENSITIVE_CREATE,
               userAuth, ADDR, TPM2B_DIGEST_Marshal,
               data, ADDR, TPM2B_SENSITIVE_DATA_Marshal)

TPMS_UNMARSHAL_2(TPMS_SENSITIVE_CREATE,
                 userAuth, TPM2B_DIGEST_Unmarshal,
                 data, TPM2B_SENSITIVE_DATA_Unmarshal)

TPMS_MARSHAL_1(TPMS_SCHEME_HASH,
               hashAlg, VAL, UINT16_Marshal)

TPMS_UNMARSHAL_1(TPMS_SCHEME_HASH,
                 hashAlg, UINT16_Unmarshal)

TPMS_MARSHAL_2(TPMS_SCHEME_ECDAA,
               hashAlg, VAL, UINT16_Marshal,
               count, VAL, UINT16_Marshal)

TPMS_UNMARSHAL_2(TPMS_SCHEME_ECDAA,
                 hashAlg, UINT16_Unmarshal,
                 count, UINT16_Unmarshal)

TPMS_MARSHAL_2(TPMS_SCHEME_XOR,
               hashAlg, VAL, UINT16_Marshal,
               kdf, VAL, UINT16_Marshal)

TPMS_UNMARSHAL_2(TPMS_SCHEME_XOR,
                 hashAlg, UINT16_Unmarshal,
                 kdf, UINT16_Unmarshal)

TPMS_MARSHAL_2(TPMS_ECC_POINT,
               x, ADDR, TPM2B_ECC_PARAMETER_Marshal,
               y, ADDR, TPM2B_ECC_PARAMETER_Marshal)

TPMS_UNMARSHAL_2(TPMS_ECC_POINT,
                 x, TPM2B_ECC_PARAMETER_Unmarshal,
                 y, TPM2B_ECC_PARAMETER_Unmarshal)

TPMS_MARSHAL_2(TPMS_SIGNATURE_RSA,
               hash, VAL, UINT16_Marshal,
               sig, ADDR, TPM2B_PUBLIC_KEY_RSA_Marshal)

TPMS_UNMARSHAL_2(TPMS_SIGNATURE_RSA,
                 hash, UINT16_Unmarshal,
                 sig, TPM2B_PUBLIC_KEY_RSA_Unmarshal)

TPMS_MARSHAL_3(TPMS_SIGNATURE_ECC,
               hash, VAL, UINT16_Marshal,
               signatureR, ADDR, TPM2B_ECC_PARAMETER_Marshal,
               signatureS, ADDR, TPM2B_ECC_PARAMETER_Marshal)

TPMS_UNMARSHAL_3(TPMS_SIGNATURE_ECC,
                 hash, UINT16_Unmarshal,
                 signatureR, TPM2B_ECC_PARAMETER_Unmarshal,
                 signatureS, TPM2B_ECC_PARAMETER_Unmarshal)

TPMS_MARSHAL_2(TPMS_NV_PIN_COUNTER_PARAMETERS,
               pinCount, VAL, UINT32_Marshal,
               pinLimit, VAL, UINT32_Marshal)

TPMS_UNMARSHAL_2(TPMS_NV_PIN_COUNTER_PARAMETERS,
                 pinCount, UINT32_Unmarshal,
                 pinLimit, UINT32_Unmarshal)

TPMS_MARSHAL_5(TPMS_NV_PUBLIC,
               nvIndex, VAL, UINT32_Marshal,
               nameAlg, VAL, UINT16_Marshal,
               attributes, VAL, TPMA_NV_Marshal,
               authPolicy, ADDR, TPM2B_DIGEST_Marshal,
               dataSize, VAL, UINT16_Marshal)

TPMS_UNMARSHAL_5(TPMS_NV_PUBLIC,
                 nvIndex, UINT32_Unmarshal,
                 nameAlg, UINT16_Unmarshal,
                 attributes, TPMA_NV_Unmarshal,
                 authPolicy, TPM2B_DIGEST_Unmarshal,
                 dataSize, UINT16_Unmarshal)

TPMS_MARSHAL_2(TPMS_CONTEXT_DATA,
               integrity, ADDR, TPM2B_DIGEST_Marshal,
               encrypted, ADDR, TPM2B_CONTEXT_SENSITIVE_Marshal)

TPMS_UNMARSHAL_2(TPMS_CONTEXT_DATA,
                 integrity, TPM2B_DIGEST_Unmarshal,
                 encrypted, TPM2B_CONTEXT_SENSITIVE_Unmarshal)

TPMS_MARSHAL_4(TPMS_CONTEXT,
               sequence, VAL, UINT64_Marshal,
               savedHandle, VAL, UINT32_Marshal,
               hierarchy, VAL, UINT32_Marshal,
               contextBlob, ADDR, TPM2B_CONTEXT_DATA_Marshal)

TPMS_UNMARSHAL_4(TPMS_CONTEXT,
                 sequence, UINT64_Unmarshal,
                 savedHandle, UINT32_Unmarshal,
                 hierarchy, UINT32_Unmarshal,
                 contextBlob, TPM2B_CONTEXT_DATA_Unmarshal)

TPMS_MARSHAL_1(TPMS_PCR_SELECT,
               sizeofSelect, ADDR, marshal_pcr_select)

TPMS_UNMARSHAL_1(TPMS_PCR_SELECT,
                 sizeofSelect, unmarshal_pcr_select)

TPMS_MARSHAL_1(TPMS_PCR_SELECTION,
               hash, ADDR, marshal_pcr_selection)

TPMS_UNMARSHAL_1(TPMS_PCR_SELECTION,
                 hash, unmarshal_pcr_selection)

TPMS_MARSHAL_1(TPMS_TAGGED_PCR_SELECT,
               tag, ADDR, marshal_tagged_pcr_selection)

TPMS_UNMARSHAL_1(TPMS_TAGGED_PCR_SELECT,
                 tag, unmarshal_tagged_pcr_selection)

TPMS_MARSHAL_2(TPMS_QUOTE_INFO,
               pcrSelect, ADDR, TPML_PCR_SELECTION_Marshal,
               pcrDigest, ADDR, TPM2B_DIGEST_Marshal)

TPMS_UNMARSHAL_2(TPMS_QUOTE_INFO,
                 pcrSelect, TPML_PCR_SELECTION_Unmarshal,
                 pcrDigest, TPM2B_DIGEST_Unmarshal)
