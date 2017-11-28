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

#include "sapi/tss2_mu.h"
#include "sapi/tpm20.h"
#include "tss2_endian.h"
#include "log.h"

static TSS2_RC marshal_tab(BYTE const *src, uint8_t buffer[],
                           size_t buffer_size, size_t *offset, size_t size)
{
    size_t local_offset = 0;

    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    }

    if (offset != NULL) {
        LOG (DEBUG, "offset non-NULL, initial value: %zu", *offset);
        local_offset = *offset;
    }

    if (buffer == NULL && offset == NULL) {
        LOG (WARNING, "buffer and offset parameter are NULL");
        return TSS2_TYPES_RC_BAD_REFERENCE;
    } else if (buffer == NULL && offset != NULL) {
        *offset += size;
        LOG (INFO, "buffer NULL and offset non-NULL, updating offset to %zu",
             *offset);
        return TSS2_RC_SUCCESS;
    } else if (buffer_size < local_offset || buffer_size - local_offset < size) {
        LOG (WARNING, "buffer_size: %zu with offset: %zu are insufficient for "
             "object of size %zu", buffer_size, local_offset, size);
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER;
    }

    LOG (DEBUG, "Marshalling TPMU tab of %d bytes from 0x%" PRIxPTR " to buffer 0x%"
         PRIxPTR " at index 0x%zx", (int)size, (uintptr_t)src, (uintptr_t)buffer,
         local_offset);

    memcpy(&buffer[local_offset], src, size);
    local_offset += size;

    if (offset) {
        *offset = local_offset;
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset);
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC marshal_hash_sha(BYTE const *src, uint8_t buffer[],
                                size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, TPM2_SHA1_DIGEST_SIZE);
}

static TSS2_RC marshal_hash_sha256(BYTE const *src, uint8_t buffer[],
                                   size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, TPM2_SHA256_DIGEST_SIZE);
}

static TSS2_RC marshal_hash_sha384(BYTE const *src, uint8_t buffer[],
                                   size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, TPM2_SHA384_DIGEST_SIZE);
}

static TSS2_RC marshal_hash_sha512(BYTE const *src, uint8_t buffer[],
                                   size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, TPM2_SHA512_DIGEST_SIZE);
}

static TSS2_RC marshal_sm3_256(BYTE const *src, uint8_t buffer[],
                               size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, TPM2_SM3_256_DIGEST_SIZE);
}

static TSS2_RC marshal_ecc(BYTE const *src, uint8_t buffer[],
                           size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, sizeof(TPMS_ECC_POINT));
}

static TSS2_RC marshal_rsa(BYTE const *src, uint8_t buffer[],
                           size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, TPM2_MAX_RSA_KEY_BYTES);
}

static TSS2_RC marshal_symmetric(BYTE const *src, uint8_t buffer[],
                                 size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, sizeof(TPM2B_DIGEST));
}

static TSS2_RC marshal_keyedhash(BYTE const *src, uint8_t buffer[],
                                 size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, sizeof(TPM2B_DIGEST));
}


static TSS2_RC marshal_null(void const *src, uint8_t buffer[],
                            size_t buffer_size, size_t *offset)
{
    return TSS2_RC_SUCCESS;
}

static TSS2_RC unmarshal_tab(uint8_t const buffer[], size_t buffer_size,
                             size_t *offset, void *dest, size_t size)
{
    size_t  local_offset = 0;

    if (offset != NULL) {
        LOG (DEBUG, "offset non-NULL, initial value: %zu", *offset);
        local_offset = *offset;
    }

    if (buffer == NULL || (dest == NULL && offset == NULL)) {
        LOG (WARNING, "buffer or dest and offset parameter are NULL");
        return TSS2_TYPES_RC_BAD_REFERENCE;
    } else if (dest == NULL && offset != NULL) {
        *offset += size;
        LOG (INFO, "buffer NULL and offset non-NULL, updating offset to %zu",
             *offset);
        return TSS2_RC_SUCCESS;
    } else if (buffer_size < local_offset || size > buffer_size - local_offset) {
        LOG (WARNING, "buffer_size: %zu with offset: %zu are insufficient for "
             "object of size %zu", buffer_size, local_offset, size);
        return TSS2_TYPES_RC_INSUFFICIENT_BUFFER;
    }

    LOG (DEBUG,
         "Marshalling TPMU tab of %d bytes from buffer 0x%" PRIxPTR " at index 0x%zx"
         " to dest 0x%" PRIxPTR, (int)size, (uintptr_t)buffer, local_offset,
         (uintptr_t)dest);

    memcpy(dest, &buffer[local_offset], size);
    local_offset += size;

    if (offset) {
        *offset = local_offset;
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset);
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC unmarshal_hash_sha(uint8_t const buffer[], size_t buffer_size,
                                  size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, TPM2_SHA1_DIGEST_SIZE);
}

static TSS2_RC unmarshal_hash_sha256(uint8_t const buffer[], size_t buffer_size,
                                     size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, TPM2_SHA256_DIGEST_SIZE);
}

static TSS2_RC unmarshal_hash_sha384(uint8_t const buffer[], size_t buffer_size,
                                     size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, TPM2_SHA384_DIGEST_SIZE);
}

static TSS2_RC unmarshal_hash_sha512(uint8_t const buffer[], size_t buffer_size,
                                     size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, TPM2_SHA512_DIGEST_SIZE);
}

static TSS2_RC unmarshal_sm3_256(uint8_t const buffer[], size_t buffer_size,
                                 size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, TPM2_SM3_256_DIGEST_SIZE);
}

static TSS2_RC unmarshal_ecc(uint8_t const buffer[], size_t buffer_size,
                             size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, sizeof(TPMS_ECC_POINT));
}

static TSS2_RC unmarshal_rsa(uint8_t const buffer[], size_t buffer_size,
                             size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, TPM2_MAX_RSA_KEY_BYTES);
}

static TSS2_RC unmarshal_symmetric(uint8_t const buffer[], size_t buffer_size,
                                   size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, sizeof(TPM2B_DIGEST));
}

static TSS2_RC unmarshal_keyedhash(uint8_t const buffer[], size_t buffer_size,
                                   size_t *offset, void *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, sizeof(TPM2B_DIGEST));
}

static TSS2_RC unmarshal_null(uint8_t const buffer[], size_t buffer_size,
                             size_t *offset, void *dest)
{
    return TSS2_RC_SUCCESS;
}

/*
 * This should not be called directly but rather via the TPMU_MARSHAL2 macro function.
 *
 * This routine is set up to handle 11 members in a union. Its arguments are the
 * type of the UNION, the selector value for that union, ie type of algorithm, and a function
 * to call for serialization.
 */
#define _TPMU_MARSHAL(type, sel, m, fn, sel2, m2, fn2, sel3, m3, fn3, \
                     sel4, m4, fn4, sel5, m5, fn5, sel6, m6, fn6, sel7, m7, fn7, \
                     sel8, m8, fn8, sel9, m9, fn9, sel10, m10, fn10, sel11, m11, fn11, ...) \
TSS2_RC Tss2_MU_##type##_Marshal(type const *src, uint32_t selector, uint8_t buffer[], \
                                 size_t buffer_size, size_t *offset) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    if (src == NULL) { \
        LOG (WARNING, "src param is NULL"); \
        return TSS2_TYPES_RC_BAD_REFERENCE; \
    } \
\
    switch (selector) { \
    case sel: \
    ret = fn(m, buffer, buffer_size, offset); \
    break; \
    case sel2: \
    ret = fn2(m2, buffer, buffer_size, offset); \
    break; \
    case sel3: \
    ret = fn3(m3, buffer, buffer_size, offset); \
    break; \
    case sel4: \
    ret = fn4(m4, buffer, buffer_size, offset); \
    break; \
    case sel5: \
    ret = fn5(m5, buffer, buffer_size, offset); \
    break; \
    case sel6: \
    ret = fn6(m6, buffer, buffer_size, offset); \
    break; \
    case sel7: \
    ret = fn7(m7, buffer, buffer_size, offset); \
    break; \
    case sel8: \
    ret = fn8(m8, buffer, buffer_size, offset); \
    break; \
    case sel9: \
    ret = fn9(m9, buffer, buffer_size, offset); \
    break; \
    case sel10: \
    ret = fn10(m10, buffer, buffer_size, offset); \
    break; \
    case sel11: \
    ret = fn11(m11, buffer, buffer_size, offset); \
    break; \
    default: \
    break; \
    } \
    return ret; \
}

/*
 * This macro function sets up a marshaling routine for marshaling TPMU types. The variadic
 * arguments and the way macro expansion work allow for flexible member parsing of the encompassing
 * union type.
 *
 * As arguments it takes:
 *  type: The type of the union to marshal
 *
 *  Repeating patterns of:
 *    selector: The selector value, which corresponds to the proper union member.
 *    member: An offset into the union of "type". Reference to the union is via the "src" variable.
 *    function: A routine that is used for performing the serialization.
 */
#define TPMU_MARSHAL(...) _TPMU_MARSHAL(__VA_ARGS__, -1, src, marshal_null, -2, src, marshal_null,\
                                        -3, src, marshal_null, -4, src, marshal_null, -5, src, marshal_null, \
                                        -6, src, marshal_null, -7, src, marshal_null, -8, src, marshal_null, \
                                        -9, src, marshal_null, -10, src, marshal_null)

/* like _TPMU_MARSHAL but for un-marshaling */
#define _TPMU_UNMARSHAL(type, sel, m, fn, sel2, m2, fn2, sel3, m3, fn3, \
                       sel4, m4, fn4, sel5, m5, fn5, sel6, m6, fn6, sel7, m7, fn7, \
                       sel8, m8, fn8, sel9, m9, fn9, sel10, m10, fn10, sel11, m11, fn11, ...) \
TSS2_RC Tss2_MU_##type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, \
                                   size_t *offset, uint32_t selector, type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    switch (selector) { \
    case sel: \
    ret = fn(buffer, buffer_size, offset, dest ? m : NULL); \
    break; \
    case sel2: \
    ret = fn2(buffer, buffer_size, offset, dest ? m2 : NULL); \
    break; \
    case sel3: \
    ret = fn3(buffer, buffer_size, offset, dest ? m3 : NULL); \
    break; \
    case sel4: \
    ret = fn4(buffer, buffer_size, offset, dest ? m4 : NULL); \
    break; \
    case sel5: \
    ret = fn5(buffer, buffer_size, offset, dest ? m5 : NULL); \
    break; \
    case sel6: \
    ret = fn6(buffer, buffer_size, offset, dest ? m6 : NULL); \
    break; \
    case sel7: \
    ret = fn7(buffer, buffer_size, offset, dest ? m7 : NULL); \
    break; \
    case sel8: \
    ret = fn8(buffer, buffer_size, offset, dest ? m8 : NULL); \
    break; \
    case sel9: \
    ret = fn9(buffer, buffer_size, offset, dest ? m9 : NULL); \
    break; \
    case sel10: \
    ret = fn10(buffer, buffer_size, offset, dest ? m10 : NULL); \
    break; \
    case sel11: \
    ret = fn11(buffer, buffer_size, offset, dest ? m11 : NULL); \
    break; \
    default: \
    break; \
    } \
    return ret; \
}

/*
 * This macro function sets up the un-marshaling routines for un-marshaling TPMU types. The variadic
 * arguments and the way macro expansion work allow for flexible member parsing of the encompassing
 * union type.
 *
 * As arguments it takes:
 *  type: The type of the union to marshal
 *
 *  Repeating patterns of:
 *    selector: The selector value, which corresponds to the proper union member.
 *    member: An offset into the union of "type". Reference to the union is via the "src" variable.
 *    function: A routine that is used for performing the serialization.
 */
#define TPMU_UNMARSHAL(...) _TPMU_UNMARSHAL(__VA_ARGS__, -1, dest, unmarshal_null, -2, dest, unmarshal_null,\
                                            -3, dest, unmarshal_null, -4, dest, unmarshal_null, -5, dest, unmarshal_null, \
                                            -6, dest, unmarshal_null, -7, dest, unmarshal_null, -8, dest, unmarshal_null, \
                                            -9, dest, unmarshal_null, -10, dest, unmarshal_null)

TPMU_MARSHAL(TPMU_HA, TPM2_ALG_SHA1, src->sha1, marshal_hash_sha,
              TPM2_ALG_SHA256, src->sha256, marshal_hash_sha256, TPM2_ALG_SHA384, src->sha384, marshal_hash_sha384,
              TPM2_ALG_SHA512, src->sha512, marshal_hash_sha512, TPM2_ALG_SM3_256, src->sm3_256, marshal_sm3_256)

TPMU_UNMARSHAL(TPMU_HA, TPM2_ALG_SHA1, dest->sha1, unmarshal_hash_sha,
                TPM2_ALG_SHA256, dest->sha256, unmarshal_hash_sha256, TPM2_ALG_SHA384, dest->sha384, unmarshal_hash_sha384,
                TPM2_ALG_SHA512, dest->sha512, unmarshal_hash_sha512, TPM2_ALG_SM3_256, dest->sm3_256, unmarshal_sm3_256)

TPMU_MARSHAL(TPMU_CAPABILITIES, TPM2_CAP_ALGS, &src->algorithms, Tss2_MU_TPML_ALG_PROPERTY_Marshal,
              TPM2_CAP_HANDLES, &src->handles, Tss2_MU_TPML_HANDLE_Marshal, TPM2_CAP_COMMANDS, &src->command, Tss2_MU_TPML_CCA_Marshal,
              TPM2_CAP_PP_COMMANDS, &src->ppCommands, Tss2_MU_TPML_CC_Marshal, TPM2_CAP_AUDIT_COMMANDS, &src->auditCommands, Tss2_MU_TPML_CC_Marshal,
              TPM2_CAP_PCRS, &src->assignedPCR, Tss2_MU_TPML_PCR_SELECTION_Marshal, TPM2_CAP_TPM_PROPERTIES, &src->tpmProperties, Tss2_MU_TPML_TAGGED_TPM_PROPERTY_Marshal,
              TPM2_CAP_PCR_PROPERTIES, &src->pcrProperties, Tss2_MU_TPML_TAGGED_PCR_PROPERTY_Marshal, TPM2_CAP_ECC_CURVES, &src->eccCurves, Tss2_MU_TPML_ECC_CURVE_Marshal,
              TPM2_CAP_VENDOR_PROPERTY, &src->intelPttProperty, Tss2_MU_TPML_INTEL_PTT_PROPERTY_Marshal)

TPMU_UNMARSHAL(TPMU_CAPABILITIES, TPM2_CAP_ALGS, &dest->algorithms, Tss2_MU_TPML_ALG_PROPERTY_Unmarshal,
                TPM2_CAP_HANDLES, &dest->handles, Tss2_MU_TPML_HANDLE_Unmarshal, TPM2_CAP_COMMANDS, &dest->command, Tss2_MU_TPML_CCA_Unmarshal,
                TPM2_CAP_PP_COMMANDS, &dest->ppCommands, Tss2_MU_TPML_CC_Unmarshal, TPM2_CAP_AUDIT_COMMANDS, &dest->auditCommands, Tss2_MU_TPML_CC_Unmarshal,
                TPM2_CAP_PCRS, &dest->assignedPCR, Tss2_MU_TPML_PCR_SELECTION_Unmarshal, TPM2_CAP_TPM_PROPERTIES, &dest->tpmProperties, Tss2_MU_TPML_TAGGED_TPM_PROPERTY_Unmarshal,
                TPM2_CAP_PCR_PROPERTIES, &dest->pcrProperties, Tss2_MU_TPML_TAGGED_PCR_PROPERTY_Unmarshal, TPM2_CAP_ECC_CURVES, &dest->eccCurves, Tss2_MU_TPML_ECC_CURVE_Unmarshal,
                TPM2_CAP_VENDOR_PROPERTY, &dest->intelPttProperty, Tss2_MU_TPML_INTEL_PTT_PROPERTY_Unmarshal)

TPMU_MARSHAL(TPMU_ATTEST, TPM2_ST_ATTEST_CERTIFY, &src->certify, Tss2_MU_TPMS_CERTIFY_INFO_Marshal,
              TPM2_ST_ATTEST_CREATION, &src->creation, Tss2_MU_TPMS_CREATION_INFO_Marshal, TPM2_ST_ATTEST_QUOTE, &src->quote, Tss2_MU_TPMS_QUOTE_INFO_Marshal,
              TPM2_ST_ATTEST_COMMAND_AUDIT, &src->commandAudit, Tss2_MU_TPMS_COMMAND_AUDIT_INFO_Marshal,
              TPM2_ST_ATTEST_SESSION_AUDIT, &src->sessionAudit, Tss2_MU_TPMS_SESSION_AUDIT_INFO_Marshal,
              TPM2_ST_ATTEST_TIME, &src->time, Tss2_MU_TPMS_TIME_ATTEST_INFO_Marshal, TPM2_ST_ATTEST_NV, &src->nv, Tss2_MU_TPMS_NV_CERTIFY_INFO_Marshal)

TPMU_UNMARSHAL(TPMU_ATTEST, TPM2_ST_ATTEST_CERTIFY, &dest->certify, Tss2_MU_TPMS_CERTIFY_INFO_Unmarshal,
                TPM2_ST_ATTEST_CREATION, &dest->creation, Tss2_MU_TPMS_CREATION_INFO_Unmarshal, TPM2_ST_ATTEST_QUOTE, &dest->quote, Tss2_MU_TPMS_QUOTE_INFO_Unmarshal,
                TPM2_ST_ATTEST_COMMAND_AUDIT, &dest->commandAudit, Tss2_MU_TPMS_COMMAND_AUDIT_INFO_Unmarshal,
                TPM2_ST_ATTEST_SESSION_AUDIT, &dest->sessionAudit, Tss2_MU_TPMS_SESSION_AUDIT_INFO_Unmarshal,
                TPM2_ST_ATTEST_TIME, &dest->time, Tss2_MU_TPMS_TIME_ATTEST_INFO_Unmarshal, TPM2_ST_ATTEST_NV, &dest->nv, Tss2_MU_TPMS_NV_CERTIFY_INFO_Unmarshal)

TPMU_MARSHAL(TPMU_SYM_KEY_BITS, TPM2_ALG_AES, src->aes, Tss2_MU_UINT16_Marshal, TPM2_ALG_SM4, src->sm4, Tss2_MU_UINT16_Marshal,
              TPM2_ALG_CAMELLIA, src->camellia, Tss2_MU_UINT16_Marshal, TPM2_ALG_XOR, src->exclusiveOr, Tss2_MU_UINT16_Marshal)

TPMU_UNMARSHAL(TPMU_SYM_KEY_BITS, TPM2_ALG_AES, &dest->aes, Tss2_MU_UINT16_Unmarshal, TPM2_ALG_SM4, &dest->sm4, Tss2_MU_UINT16_Unmarshal,
              TPM2_ALG_CAMELLIA, &dest->camellia, Tss2_MU_UINT16_Unmarshal, TPM2_ALG_XOR, &dest->exclusiveOr, Tss2_MU_UINT16_Unmarshal)

TPMU_MARSHAL(TPMU_SYM_MODE, TPM2_ALG_AES, src->aes, Tss2_MU_UINT16_Marshal, TPM2_ALG_SM4, src->sm4, Tss2_MU_UINT16_Marshal,
              TPM2_ALG_CAMELLIA, src->camellia, Tss2_MU_UINT16_Marshal)

TPMU_UNMARSHAL(TPMU_SYM_MODE, TPM2_ALG_AES, &dest->aes, Tss2_MU_UINT16_Unmarshal, TPM2_ALG_SM4, &dest->sm4, Tss2_MU_UINT16_Unmarshal,
              TPM2_ALG_CAMELLIA, &dest->camellia, Tss2_MU_UINT16_Unmarshal)

TPMU_MARSHAL(TPMU_SIG_SCHEME, TPM2_ALG_RSASSA, &src->rsassa, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_RSAPSS, &src->rsapss, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECDSA, &src->ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECDAA, &src->ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Marshal,
              TPM2_ALG_SM2, &src->sm2, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECSCHNORR, &src->ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_HMAC, &src->hmac, Tss2_MU_TPMS_SCHEME_HASH_Marshal)

TPMU_UNMARSHAL(TPMU_SIG_SCHEME, TPM2_ALG_RSASSA, &dest->rsassa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_RSAPSS, &dest->rsapss, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECDSA, &dest->ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECDAA, &dest->ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Unmarshal,
                TPM2_ALG_SM2, &dest->sm2, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECSCHNORR, &dest->ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_HMAC, &dest->hmac, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal)

TPMU_MARSHAL(TPMU_KDF_SCHEME, TPM2_ALG_MGF1, &src->mgf1, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_KDF1_SP800_56A, &src->kdf1_sp800_56a, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_KDF1_SP800_108, &src->kdf1_sp800_108, Tss2_MU_TPMS_SCHEME_HASH_Marshal)

TPMU_UNMARSHAL(TPMU_KDF_SCHEME, TPM2_ALG_MGF1, &dest->mgf1, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_KDF1_SP800_56A, &dest->kdf1_sp800_56a, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_KDF1_SP800_108, &dest->kdf1_sp800_108, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal)

TPMU_MARSHAL(TPMU_ASYM_SCHEME, TPM2_ALG_ECDH, &src->ecdh, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECMQV, &src->ecmqv, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_RSASSA, &src->rsassa, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_RSAPSS, &src->rsapss, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECDSA, &src->ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECDAA, &src->ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Marshal,
              TPM2_ALG_SM2, &src->sm2, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECSCHNORR, &src->ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_OAEP, &src->oaep, Tss2_MU_TPMS_SCHEME_HASH_Marshal)

TPMU_UNMARSHAL(TPMU_ASYM_SCHEME, TPM2_ALG_ECDH, &dest->ecdh, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECMQV, &dest->ecmqv, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_RSASSA, &dest->rsassa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_RSAPSS, &dest->rsapss, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECDSA, &dest->ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECDAA, &dest->ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Unmarshal,
                TPM2_ALG_SM2, &dest->sm2, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECSCHNORR, &dest->ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_OAEP, &dest->oaep, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal)

TPMU_MARSHAL(TPMU_SCHEME_KEYEDHASH, TPM2_ALG_HMAC, &src->hmac, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_XOR, &src->exclusiveOr, Tss2_MU_TPMS_SCHEME_XOR_Marshal)

TPMU_UNMARSHAL(TPMU_SCHEME_KEYEDHASH, TPM2_ALG_HMAC, &dest->hmac, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_XOR, &dest->exclusiveOr, Tss2_MU_TPMS_SCHEME_XOR_Unmarshal)

TPMU_MARSHAL(TPMU_SIGNATURE, TPM2_ALG_RSASSA, &src->rsassa, Tss2_MU_TPMS_SIGNATURE_RSA_Marshal,
              TPM2_ALG_RSAPSS, &src->rsapss, Tss2_MU_TPMS_SIGNATURE_RSA_Marshal,
              TPM2_ALG_ECDSA, &src->ecdsa, Tss2_MU_TPMS_SIGNATURE_ECC_Marshal,
              TPM2_ALG_ECDAA, &src->ecdaa, Tss2_MU_TPMS_SIGNATURE_ECC_Marshal,
              TPM2_ALG_SM2, &src->sm2, Tss2_MU_TPMS_SIGNATURE_ECC_Marshal,
              TPM2_ALG_ECSCHNORR, &src->ecschnorr, Tss2_MU_TPMS_SIGNATURE_ECC_Marshal,
              TPM2_ALG_HMAC, &src->hmac, Tss2_MU_TPMT_HA_Marshal)

TPMU_UNMARSHAL(TPMU_SIGNATURE, TPM2_ALG_RSASSA, &dest->rsassa, Tss2_MU_TPMS_SIGNATURE_RSA_Unmarshal,
                TPM2_ALG_RSAPSS, &dest->rsapss, Tss2_MU_TPMS_SIGNATURE_RSA_Unmarshal,
                TPM2_ALG_ECDSA, &dest->ecdsa, Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal,
                TPM2_ALG_ECDAA, &dest->ecdaa, Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal,
                TPM2_ALG_SM2, &dest->sm2, Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal,
                TPM2_ALG_ECSCHNORR, &dest->ecschnorr, Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal,
                TPM2_ALG_HMAC, &dest->hmac, Tss2_MU_TPMT_HA_Unmarshal)

TPMU_MARSHAL(TPMU_SENSITIVE_COMPOSITE, TPM2_ALG_RSA, &src->rsa, Tss2_MU_TPM2B_PRIVATE_KEY_RSA_Marshal,
              TPM2_ALG_ECC, &src->ecc, Tss2_MU_TPM2B_ECC_PARAMETER_Marshal,
              TPM2_ALG_KEYEDHASH, &src->bits, Tss2_MU_TPM2B_SENSITIVE_DATA_Marshal,
              TPM2_ALG_SYMCIPHER, &src->sym, Tss2_MU_TPM2B_SYM_KEY_Marshal)

TPMU_UNMARSHAL(TPMU_SENSITIVE_COMPOSITE, TPM2_ALG_RSA, &dest->rsa, Tss2_MU_TPM2B_PRIVATE_KEY_RSA_Unmarshal,
                TPM2_ALG_ECC, &dest->ecc, Tss2_MU_TPM2B_ECC_PARAMETER_Unmarshal,
                TPM2_ALG_KEYEDHASH, &dest->bits, Tss2_MU_TPM2B_SENSITIVE_DATA_Unmarshal,
                TPM2_ALG_SYMCIPHER, &dest->sym, Tss2_MU_TPM2B_SYM_KEY_Unmarshal)

TPMU_MARSHAL(TPMU_ENCRYPTED_SECRET, TPM2_ALG_ECC, src->ecc, marshal_ecc,
              TPM2_ALG_RSA, src->rsa, marshal_rsa,
              TPM2_ALG_SYMCIPHER, src->symmetric, marshal_symmetric,
              TPM2_ALG_KEYEDHASH, src->keyedHash, marshal_keyedhash)

TPMU_UNMARSHAL(TPMU_ENCRYPTED_SECRET, TPM2_ALG_ECC, dest->ecc, unmarshal_ecc,
                TPM2_ALG_RSA, &dest->rsa, unmarshal_rsa,
                TPM2_ALG_SYMCIPHER, &dest->symmetric, unmarshal_symmetric,
                TPM2_ALG_KEYEDHASH, &dest->keyedHash, unmarshal_keyedhash)

TPMU_MARSHAL(TPMU_PUBLIC_ID, TPM2_ALG_KEYEDHASH, &src->keyedHash, Tss2_MU_TPM2B_DIGEST_Marshal,
              TPM2_ALG_SYMCIPHER, &src->sym, Tss2_MU_TPM2B_DIGEST_Marshal,
              TPM2_ALG_RSA, &src->rsa, Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Marshal,
              TPM2_ALG_ECC, &src->ecc, Tss2_MU_TPMS_ECC_POINT_Marshal)

TPMU_UNMARSHAL(TPMU_PUBLIC_ID, TPM2_ALG_KEYEDHASH, &dest->keyedHash, Tss2_MU_TPM2B_DIGEST_Unmarshal,
                TPM2_ALG_SYMCIPHER, &dest->sym, Tss2_MU_TPM2B_DIGEST_Unmarshal,
                TPM2_ALG_RSA, &dest->rsa, Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Unmarshal,
                TPM2_ALG_ECC, &dest->ecc, Tss2_MU_TPMS_ECC_POINT_Unmarshal)

TPMU_MARSHAL(TPMU_PUBLIC_PARMS, TPM2_ALG_KEYEDHASH, &src->keyedHashDetail, Tss2_MU_TPMS_KEYEDHASH_PARMS_Marshal,
              TPM2_ALG_SYMCIPHER, &src->symDetail, Tss2_MU_TPMS_SYMCIPHER_PARMS_Marshal,
              TPM2_ALG_RSA, &src->rsaDetail, Tss2_MU_TPMS_RSA_PARMS_Marshal,
              TPM2_ALG_ECC, &src->eccDetail, Tss2_MU_TPMS_ECC_PARMS_Marshal)

TPMU_UNMARSHAL(TPMU_PUBLIC_PARMS, TPM2_ALG_KEYEDHASH, &dest->keyedHashDetail, Tss2_MU_TPMS_KEYEDHASH_PARMS_Unmarshal,
                TPM2_ALG_SYMCIPHER, &dest->symDetail, Tss2_MU_TPMS_SYMCIPHER_PARMS_Unmarshal,
                TPM2_ALG_RSA, &dest->rsaDetail, Tss2_MU_TPMS_RSA_PARMS_Unmarshal,
                TPM2_ALG_ECC, &dest->eccDetail, Tss2_MU_TPMS_ECC_PARMS_Unmarshal)
