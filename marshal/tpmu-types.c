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

    if (offset != NULL) {
        *offset += local_offset - *offset;
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset);
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC marshal_hash_sha(BYTE const *src, uint8_t buffer[],
                                size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, SHA1_DIGEST_SIZE);
}

static TSS2_RC marshal_hash_sha256(BYTE const *src, uint8_t buffer[],
                                   size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, SHA256_DIGEST_SIZE);
}

static TSS2_RC marshal_hash_sha384(BYTE const *src, uint8_t buffer[],
                                   size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, SHA384_DIGEST_SIZE);
}

static TSS2_RC marshal_hash_sha512(BYTE const *src, uint8_t buffer[],
                                   size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, SHA512_DIGEST_SIZE);
}

static TSS2_RC marshal_sm3_256(BYTE const *src, uint8_t buffer[],
                               size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, SM3_256_DIGEST_SIZE);
}

static TSS2_RC marshal_ecc(BYTE const *src, uint8_t buffer[],
                           size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, sizeof(TPMS_ECC_POINT));
}

static TSS2_RC marshal_rsa(BYTE const *src, uint8_t buffer[],
                           size_t buffer_size, size_t *offset)
{
    return marshal_tab(src, buffer, buffer_size, offset, MAX_RSA_KEY_BYTES);
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


static TSS2_RC marshal_null(char const *src, uint8_t buffer[],
                            size_t buffer_size, size_t *offset)
{
    return TSS2_RC_SUCCESS;
}

static TSS2_RC unmarshal_tab(uint8_t const buffer[], size_t buffer_size,
                             size_t *offset, BYTE *dest, size_t size)
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

    if (offset != NULL) {
        *offset += local_offset - *offset;
        LOG (DEBUG, "offset parameter non-NULL, updated to %zu", *offset);
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC unmarshal_hash_sha(uint8_t const buffer[], size_t buffer_size,
                                  size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, SHA1_DIGEST_SIZE);
}

static TSS2_RC unmarshal_hash_sha256(uint8_t const buffer[], size_t buffer_size,
                                     size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, SHA256_DIGEST_SIZE);
}

static TSS2_RC unmarshal_hash_sha384(uint8_t const buffer[], size_t buffer_size,
                                     size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, SHA384_DIGEST_SIZE);
}

static TSS2_RC unmarshal_hash_sha512(uint8_t const buffer[], size_t buffer_size,
                                     size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, SHA512_DIGEST_SIZE);
}

static TSS2_RC unmarshal_sm3_256(uint8_t const buffer[], size_t buffer_size,
                                 size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, SM3_256_DIGEST_SIZE);
}

static TSS2_RC unmarshal_ecc(uint8_t const buffer[], size_t buffer_size,
                             size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, sizeof(TPMS_ECC_POINT));
}

static TSS2_RC unmarshal_rsa(uint8_t const buffer[], size_t buffer_size,
                             size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, MAX_RSA_KEY_BYTES);
}

static TSS2_RC unmarshal_symmetric(uint8_t const buffer[], size_t buffer_size,
                                   size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, sizeof(TPM2B_DIGEST));
}

static TSS2_RC unmarshal_keyedhash(uint8_t const buffer[], size_t buffer_size,
                                   size_t *offset, BYTE *dest)
{
    return unmarshal_tab(buffer, buffer_size, offset, dest, sizeof(TPM2B_DIGEST));
}

static TSS2_RC unmashal_null(uint8_t const buffer[], size_t buffer_size,
                             size_t *offset, char *dest)
{
    return TSS2_RC_SUCCESS;
}

#define TPMU_MARSHAL(type, sel, op, m, fn, sel2, op2, m2, fn2, sel3, op3, m3, fn3, \
                     sel4, op4, m4, fn4, sel5, op5, m5, fn5, sel6, op6, m6, fn6, sel7, op7, m7, fn7, \
                     sel8, op8, m8, fn8, sel9, op9, m9, fn9, sel10, op10, m10, fn10, sel11, op11, m11, fn11, ...) \
TSS2_RC type##_Marshal(type const *src, uint32_t selector, uint8_t buffer[], \
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
    ret = fn(op src->m, buffer, buffer_size, offset); \
    break; \
    case sel2: \
    ret = fn2(op2 src->m2, buffer, buffer_size, offset); \
    break; \
    case sel3: \
    ret = fn3(op3 src->m3, buffer, buffer_size, offset); \
    break; \
    case sel4: \
    ret = fn4(op4 src->m4, buffer, buffer_size, offset); \
    break; \
    case sel5: \
    ret = fn5(op5 src->m5, buffer, buffer_size, offset); \
    break; \
    case sel6: \
    ret = fn6(op6 src->m6, buffer, buffer_size, offset); \
    break; \
    case sel7: \
    ret = fn7(op7 src->m7, buffer, buffer_size, offset); \
    break; \
    case sel8: \
    ret = fn8(op8 src->m8, buffer, buffer_size, offset); \
    break; \
    case sel9: \
    ret = fn9(op9 src->m9, buffer, buffer_size, offset); \
    break; \
    case sel10: \
    ret = fn10(op10 src->m10, buffer, buffer_size, offset); \
    break; \
    case sel11: \
    ret = fn11(op11 src->m11, buffer, buffer_size, offset); \
    break; \
    default: \
        break; \
    } \
    return ret; \
}

#define TPMU_MARSHAL2(...) TPMU_MARSHAL(__VA_ARGS__, -1, ADDR, na, marshal_null, -2, ADDR, na, marshal_null,\
                                        -3, ADDR, na, marshal_null, -4, ADDR, na, marshal_null, -5, ADDR, na, marshal_null, \
                                        -6, ADDR, na, marshal_null, -7, ADDR, na, marshal_null, -8, ADDR, na, marshal_null, \
                                        -9, ADDR, na, marshal_null, -10, ADDR, na, marshal_null)

#define TPMU_UNMARSHAL(type, sel, m, fn, sel2, m2, fn2, sel3, m3, fn3, \
                       sel4, m4, fn4, sel5, m5, fn5, sel6, m6, fn6, sel7, m7, fn7, \
                       sel8, m8, fn8, sel9, m9, fn9, sel10, m10, fn10, sel11, m11, fn11, ...) \
TSS2_RC type##_Unmarshal(uint8_t const buffer[], size_t buffer_size, size_t *offset, \
                         uint32_t selector, type *dest) \
{ \
    TSS2_RC ret = TSS2_RC_SUCCESS; \
\
    switch (selector) { \
    case sel: \
    ret = fn(buffer, buffer_size, offset, dest ? &dest->m : NULL); \
    break; \
    case sel2: \
    break; \
    ret = fn2(buffer, buffer_size, offset, dest ? &dest->m2 : NULL); \
    break; \
    case sel3: \
    break; \
    ret = fn3(buffer, buffer_size, offset, dest ? &dest->m3 : NULL); \
    break; \
    case sel4: \
    break; \
    ret = fn4(buffer, buffer_size, offset, dest ? &dest->m4 : NULL); \
    break; \
    case sel5: \
    break; \
    ret = fn5(buffer, buffer_size, offset, dest ? &dest->m5 : NULL); \
    break; \
    case sel6: \
    ret = fn6(buffer, buffer_size, offset, dest ? &dest->m6 : NULL); \
    break; \
    case sel7: \
    ret = fn7(buffer, buffer_size, offset, dest ? &dest->m7 : NULL); \
    break; \
    case sel8: \
    ret = fn8(buffer, buffer_size, offset, dest ? &dest->m8 : NULL); \
    break; \
    case sel9: \
    ret = fn9(buffer, buffer_size, offset, dest ? &dest->m9 : NULL); \
    break; \
    case sel10: \
    ret = fn10(buffer, buffer_size, offset, dest ? &dest->m10 : NULL); \
    break; \
    case sel11: \
    ret = fn11(buffer, buffer_size, offset, dest ? &dest->m11 : NULL); \
    break; \
    default: \
        break; \
    } \
    return ret; \
}

#define TPMU_UNMARSHAL2(...) TPMU_UNMARSHAL(__VA_ARGS__, -1, na, unmashal_null, -2, na, unmashal_null,\
                                            -3, na, unmashal_null, -4, na, unmashal_null, -5, na, unmashal_null, \
                                            -6, na, unmashal_null, -7, na, unmashal_null, -8, na, unmashal_null, \
                                            -9, na, unmashal_null, -10, na, unmashal_null)

TPMU_MARSHAL2(TPMU_HA, TPM_ALG_SHA1, ADDR, sha1[0], marshal_hash_sha, \
              TPM_ALG_SHA256, ADDR, sha256[0], marshal_hash_sha256, TPM_ALG_SHA384, ADDR, sha384[0], marshal_hash_sha384,\
              TPM_ALG_SHA512, ADDR, sha512[0], marshal_hash_sha512, TPM_ALG_SM3_256, ADDR, sm3_256[0], marshal_sm3_256)

TPMU_UNMARSHAL2(TPMU_HA, TPM_ALG_SHA1, sha1[0], unmarshal_hash_sha, \
                TPM_ALG_SHA256, sha256[0], unmarshal_hash_sha256, TPM_ALG_SHA384, sha384[0], unmarshal_hash_sha384,\
                TPM_ALG_SHA512, sha512[0], unmarshal_hash_sha512, TPM_ALG_SM3_256, sm3_256[0], unmarshal_sm3_256)

TPMU_MARSHAL2(TPMU_CAPABILITIES, TPM_CAP_ALGS, ADDR, algorithms, TPML_ALG_PROPERTY_Marshal, \
              TPM_CAP_HANDLES, ADDR, handles, TPML_HANDLE_Marshal, TPM_CAP_COMMANDS, ADDR, command, TPML_CCA_Marshal,\
              TPM_CAP_PP_COMMANDS, ADDR, ppCommands, TPML_CC_Marshal, TPM_CAP_AUDIT_COMMANDS, ADDR, auditCommands, TPML_CC_Marshal,
              TPM_CAP_PCRS, ADDR, assignedPCR, TPML_PCR_SELECTION_Marshal, TPM_CAP_TPM_PROPERTIES, ADDR, tpmProperties, TPML_TAGGED_TPM_PROPERTY_Marshal,
              TPM_CAP_PCR_PROPERTIES, ADDR, pcrProperties, TPML_TAGGED_PCR_PROPERTY_Marshal, TPM_CAP_ECC_CURVES, ADDR, eccCurves, TPML_ECC_CURVE_Marshal)

TPMU_UNMARSHAL2(TPMU_CAPABILITIES, TPM_CAP_ALGS, algorithms, TPML_ALG_PROPERTY_Unmarshal, \
                TPM_CAP_HANDLES, handles, TPML_HANDLE_Unmarshal, TPM_CAP_COMMANDS, command, TPML_CCA_Unmarshal,\
                TPM_CAP_PP_COMMANDS, ppCommands, TPML_CC_Unmarshal, TPM_CAP_AUDIT_COMMANDS, auditCommands, TPML_CC_Unmarshal,
                TPM_CAP_PCRS, assignedPCR, TPML_PCR_SELECTION_Unmarshal, TPM_CAP_TPM_PROPERTIES, tpmProperties, TPML_TAGGED_TPM_PROPERTY_Unmarshal,
                TPM_CAP_PCR_PROPERTIES, pcrProperties, TPML_TAGGED_PCR_PROPERTY_Unmarshal, TPM_CAP_ECC_CURVES, eccCurves, TPML_ECC_CURVE_Unmarshal)

TPMU_MARSHAL2(TPMU_ATTEST, TPM_ST_ATTEST_CERTIFY, ADDR, certify, TPMS_CERTIFY_INFO_Marshal, \
              TPM_ST_ATTEST_CREATION, ADDR, creation, TPMS_CREATION_INFO_Marshal, TPM_ST_ATTEST_QUOTE, ADDR, quote, TPMS_QUOTE_INFO_Marshal,\
              TPM_ST_ATTEST_COMMAND_AUDIT, ADDR, commandAudit, TPMS_COMMAND_AUDIT_INFO_Marshal, \
              TPM_ST_ATTEST_SESSION_AUDIT, ADDR, sessionAudit, TPMS_SESSION_AUDIT_INFO_Marshal,
              TPM_ST_ATTEST_TIME, ADDR, time, TPMS_TIME_ATTEST_INFO_Marshal, TPM_ST_ATTEST_NV, ADDR, nv, TPMS_NV_CERTIFY_INFO_Marshal)

TPMU_UNMARSHAL2(TPMU_ATTEST, TPM_ST_ATTEST_CERTIFY, certify, TPMS_CERTIFY_INFO_Unmarshal, \
                TPM_ST_ATTEST_CREATION, creation, TPMS_CREATION_INFO_Unmarshal, TPM_ST_ATTEST_QUOTE, quote, TPMS_QUOTE_INFO_Unmarshal,\
                TPM_ST_ATTEST_COMMAND_AUDIT, commandAudit, TPMS_COMMAND_AUDIT_INFO_Unmarshal, \
                TPM_ST_ATTEST_SESSION_AUDIT, sessionAudit, TPMS_SESSION_AUDIT_INFO_Unmarshal,
                TPM_ST_ATTEST_TIME, time, TPMS_TIME_ATTEST_INFO_Unmarshal, TPM_ST_ATTEST_NV, nv, TPMS_NV_CERTIFY_INFO_Unmarshal)

TPMU_MARSHAL2(TPMU_SYM_KEY_BITS, TPM_ALG_AES, VAL, aes, UINT16_Marshal, TPM_ALG_SM4, VAL, sm4, UINT16_Marshal, \
              TPM_ALG_CAMELLIA, VAL, camellia, UINT16_Marshal, TPM_ALG_XOR, VAL, exclusiveOr, UINT16_Marshal)

TPMU_UNMARSHAL2(TPMU_SYM_KEY_BITS, TPM_ALG_AES, aes, UINT16_Unmarshal, TPM_ALG_SM4, sm4, UINT16_Unmarshal, \
              TPM_ALG_CAMELLIA, camellia, UINT16_Unmarshal, TPM_ALG_XOR, exclusiveOr, UINT16_Unmarshal)

TPMU_MARSHAL2(TPMU_SYM_MODE, TPM_ALG_AES, VAL, aes, UINT16_Marshal, TPM_ALG_SM4, VAL, sm4, UINT16_Marshal, \
              TPM_ALG_CAMELLIA, VAL, camellia, UINT16_Marshal)

TPMU_UNMARSHAL2(TPMU_SYM_MODE, TPM_ALG_AES, aes, UINT16_Unmarshal, TPM_ALG_SM4, sm4, UINT16_Unmarshal, \
              TPM_ALG_CAMELLIA, camellia, UINT16_Unmarshal)

TPMU_MARSHAL2(TPMU_SIG_SCHEME, TPM_ALG_RSASSA, ADDR, rsassa, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_RSAPSS, ADDR, rsapss, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_ECDSA, ADDR, ecdsa, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_ECDAA, ADDR, ecdaa, TPMS_SCHEME_ECDAA_Marshal, \
              TPM_ALG_SM2, ADDR, sm2, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_ECSCHNORR, ADDR, ecschnorr, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_HMAC, ADDR, hmac, TPMS_SCHEME_HASH_Marshal)

TPMU_UNMARSHAL2(TPMU_SIG_SCHEME, TPM_ALG_RSASSA, rsassa, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_RSAPSS, rsapss, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_ECDSA, ecdsa, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_ECDAA, ecdaa, TPMS_SCHEME_ECDAA_Unmarshal, \
                TPM_ALG_SM2, sm2, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_ECSCHNORR, ecschnorr, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_HMAC, hmac, TPMS_SCHEME_HASH_Unmarshal)

TPMU_MARSHAL2(TPMU_KDF_SCHEME, TPM_ALG_MGF1, ADDR, mgf1, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_KDF1_SP800_56A, ADDR, kdf1_sp800_56a, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_KDF1_SP800_108, ADDR, kdf1_sp800_108, TPMS_SCHEME_HASH_Marshal)

TPMU_UNMARSHAL2(TPMU_KDF_SCHEME, TPM_ALG_MGF1, mgf1, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_KDF1_SP800_56A, kdf1_sp800_56a, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_KDF1_SP800_108, kdf1_sp800_108, TPMS_SCHEME_HASH_Unmarshal)

TPMU_MARSHAL2(TPMU_ASYM_SCHEME, TPM_ALG_ECDH, ADDR, ecdh, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_ECMQV, ADDR, ecmqv, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_RSASSA, ADDR, rsassa, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_RSAPSS, ADDR, rsapss, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_ECDSA, ADDR, ecdsa, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_ECDAA, ADDR, ecdaa, TPMS_SCHEME_ECDAA_Marshal, \
              TPM_ALG_SM2, ADDR, sm2, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_ECSCHNORR, ADDR, ecschnorr, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_OAEP, ADDR, oaep, TPMS_SCHEME_HASH_Marshal)

TPMU_UNMARSHAL2(TPMU_ASYM_SCHEME, TPM_ALG_ECDH, ecdh, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_ECMQV, ecmqv, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_RSASSA, rsassa, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_RSAPSS, rsapss, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_ECDSA, ecdsa, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_ECDAA, ecdaa, TPMS_SCHEME_ECDAA_Unmarshal, \
                TPM_ALG_SM2, sm2, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_ECSCHNORR, ecschnorr, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_OAEP, oaep, TPMS_SCHEME_HASH_Unmarshal)

TPMU_MARSHAL2(TPMU_SCHEME_KEYEDHASH, TPM_ALG_HMAC, ADDR, hmac, TPMS_SCHEME_HASH_Marshal, \
              TPM_ALG_XOR, ADDR, exclusiveOr, TPMS_SCHEME_XOR_Marshal)

TPMU_UNMARSHAL2(TPMU_SCHEME_KEYEDHASH, TPM_ALG_HMAC, hmac, TPMS_SCHEME_HASH_Unmarshal, \
                TPM_ALG_XOR, exclusiveOr, TPMS_SCHEME_XOR_Unmarshal)

TPMU_MARSHAL2(TPMU_SIGNATURE, TPM_ALG_RSASSA, ADDR, rsassa, TPMS_SIGNATURE_RSA_Marshal, \
              TPM_ALG_RSAPSS, ADDR, rsapss, TPMS_SIGNATURE_RSA_Marshal, \
              TPM_ALG_ECDSA, ADDR, ecdsa, TPMS_SIGNATURE_ECC_Marshal, \
              TPM_ALG_ECDAA, ADDR, ecdaa, TPMS_SIGNATURE_ECC_Marshal, \
              TPM_ALG_SM2, ADDR, sm2, TPMS_SIGNATURE_ECC_Marshal, \
              TPM_ALG_ECSCHNORR, ADDR, ecschnorr, TPMS_SIGNATURE_ECC_Marshal)

TPMU_UNMARSHAL2(TPMU_SIGNATURE, TPM_ALG_RSASSA, rsassa, TPMS_SIGNATURE_RSA_Unmarshal, \
                TPM_ALG_RSAPSS, rsapss, TPMS_SIGNATURE_RSA_Unmarshal, \
                TPM_ALG_ECDSA, ecdsa, TPMS_SIGNATURE_ECC_Unmarshal, \
                TPM_ALG_ECDAA, ecdaa, TPMS_SIGNATURE_ECC_Unmarshal, \
                TPM_ALG_SM2, sm2, TPMS_SIGNATURE_ECC_Unmarshal, \
                TPM_ALG_ECSCHNORR, ecschnorr, TPMS_SIGNATURE_ECC_Unmarshal)

TPMU_MARSHAL2(TPMU_SENSITIVE_COMPOSITE, TPM_ALG_RSA, ADDR, rsa, TPM2B_PRIVATE_KEY_RSA_Marshal, \
              TPM_ALG_ECC, ADDR, ecc, TPM2B_ECC_PARAMETER_Marshal, \
              TPM_ALG_KEYEDHASH, ADDR, bits, TPM2B_SENSITIVE_DATA_Marshal, \
              TPM_ALG_SYMCIPHER, ADDR, sym, TPM2B_SYM_KEY_Marshal)

TPMU_UNMARSHAL2(TPMU_SENSITIVE_COMPOSITE, TPM_ALG_RSA, rsa, TPM2B_PRIVATE_KEY_RSA_Unmarshal, \
                TPM_ALG_ECC, ecc, TPM2B_ECC_PARAMETER_Unmarshal, \
                TPM_ALG_KEYEDHASH, bits, TPM2B_SENSITIVE_DATA_Unmarshal, \
                TPM_ALG_SYMCIPHER, sym, TPM2B_SYM_KEY_Unmarshal)

TPMU_MARSHAL2(TPMU_ENCRYPTED_SECRET, TPM_ALG_ECC, ADDR, ecc[0], marshal_ecc, \
              TPM_ALG_RSA, ADDR, rsa[0], marshal_rsa, \
              TPM_ALG_SYMCIPHER, ADDR, symmetric[0], marshal_symmetric, \
              TPM_ALG_KEYEDHASH, ADDR, keyedHash[0], marshal_keyedhash)

TPMU_UNMARSHAL2(TPMU_ENCRYPTED_SECRET, TPM_ALG_ECC, ecc[0], unmarshal_ecc, \
                TPM_ALG_RSA, rsa[0], unmarshal_rsa, \
                TPM_ALG_SYMCIPHER, symmetric[0], unmarshal_symmetric, \
                TPM_ALG_KEYEDHASH, keyedHash[0], unmarshal_keyedhash)
