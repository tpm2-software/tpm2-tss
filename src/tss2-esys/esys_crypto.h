/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef ESYS_CRYPTO_H
#define ESYS_CRYPTO_H

#include <stddef.h>
#include "tss2_tpm2_types.h"
#include "tss2-sys/sysapi_util.h"
#if defined(OSSL)
#include "esys_crypto_ossl.h"
#elif defined(MBED)
#include "esys_crypto_mbed.h"
#else
#include "esys_crypto_gcrypt.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE_IN_BYTES 16

TSS2_RC iesys_crypto_hash_get_digest_size(TPM2_ALG_ID hashAlg, size_t *size);

TSS2_RC iesys_crypto_pHash(
    TPM2_ALG_ID alg,
    const uint8_t rcBuffer[4],
    const uint8_t ccBuffer[4],
    const TPM2B_NAME *name1,
    const TPM2B_NAME *name2,
    const TPM2B_NAME *name3,
    const uint8_t *pBuffer,
    size_t pBuffer_size,
    uint8_t *pHash,
    size_t *pHash_size);

#define iesys_crypto_cpHash(alg, ccBuffer, name1, name2, name3, \
                            cpBuffer, cpBuffer_size, cpHash, cpHash_size) \
        iesys_crypto_pHash(alg, NULL, ccBuffer, name1, name2, name3, cpBuffer, \
                           cpBuffer_size, cpHash, cpHash_size)
#define iesys_crypto_rpHash(alg, rcBuffer, ccBuffer, rpBuffer, rpBuffer_size, \
                            rpHash, rpHash_size)                        \
        iesys_crypto_pHash(alg, rcBuffer, ccBuffer, NULL, NULL, NULL, rpBuffer, \
                           rpBuffer_size, rpHash, rpHash_size)


TSS2_RC iesys_crypto_authHmac(
    TPM2_ALG_ID alg,
    uint8_t *hmacKey,
    size_t hmacKeySize,
    const uint8_t *pHash,
    size_t pHash_size,
    const TPM2B_NONCE *nonceNewer,
    const TPM2B_NONCE *nonceOlder,
    const TPM2B_NONCE *nonceDecrypt,
    const TPM2B_NONCE *nonceEncrypt,
    TPMA_SESSION sessionAttributes,
    TPM2B_AUTH *hmac);

TSS2_RC iesys_crypto_KDFaHmac(
    TPM2_ALG_ID alg,
    uint8_t *hmacKey,
    size_t hmacKeySize,
    uint32_t counter,
    const char *label,
    TPM2B_NONCE *contextU,
    TPM2B_NONCE *contextV,
    uint32_t bitlength,
    uint8_t *hmac,
    size_t *hmacSize);

TSS2_RC iesys_crypto_KDFa(
    TPM2_ALG_ID hashAlg,
    uint8_t *hmacKey,
    size_t hmacKeySize,
    const char *label,
    TPM2B_NONCE *contextU,
    TPM2B_NONCE *contextV,
    uint32_t bitLength,
    uint32_t *counterInOut,
    BYTE *outKey,
    BOOL use_digest_size);

TSS2_RC iesys_xor_parameter_obfuscation(
    TPM2_ALG_ID hash_alg,
    uint8_t *key,
    size_t key_size,
    TPM2B_NONCE * contextU,
    TPM2B_NONCE * contextV,
    BYTE *data,
    size_t data_size);

TSS2_RC iesys_crypto_KDFe(
    TPM2_ALG_ID hashAlg,
    TPM2B_ECC_PARAMETER *Z,
    const char *label,
    TPM2B_ECC_PARAMETER *partyUInfo,
    TPM2B_ECC_PARAMETER *partyVInfo,
    UINT32 bit_size,
    BYTE *key);

TSS2_RC iesys_initialize_crypto();

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ESYS_CRYPTO_H */
