/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
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
 *******************************************************************************/
#ifndef ESYS_CRYPTO_H
#define ESYS_CRYPTO_H

#include <sapi/tss2_common.h>
#ifndef TSS2_API_VERSION_1_2_1_108
#error Version missmatch among TSS2 header files !
#endif  /* TSS2_API_VERSION_1_2_1_108 */

#include <stdint.h>
#include <stddef.h>
#include <sapi/tss2_tpm2_types.h>

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup iesys
 * @{
 */

#define AES_BLOCK_SIZE_IN_BYTES 16

typedef struct _IESYS_CRYPTO_CONTEXT IESYS_CRYPTO_CONTEXT_BLOB;

TSS2_RC iesys_crypto_hash_get_digest_size(TPM2_ALG_ID hashAlg, size_t *size);

TSS2_RC iesys_crypto_hash_get_block_size(TPM2_ALG_ID hashAlg, size_t *size);

TSS2_RC iesys_cryptogcry_hash_start(
    IESYS_CRYPTO_CONTEXT_BLOB **context,
    TPM2_ALG_ID hashAlg);

TSS2_RC iesys_cryptogcry_hash_update(
    IESYS_CRYPTO_CONTEXT_BLOB *context,
    const uint8_t *buffer, size_t size);

TSS2_RC iesys_cryptogcry_hash_update2b(
    IESYS_CRYPTO_CONTEXT_BLOB *context,
    TPM2B *b);

TSS2_RC iesys_cryptogcry_hash_finish(
    IESYS_CRYPTO_CONTEXT_BLOB **context,
    uint8_t *buffer,
    size_t *size);

TSS2_RC iesys_cryptogcry_hash_finish2b(
    IESYS_CRYPTO_CONTEXT_BLOB **context,
    TPM2B *b);

void iesys_cryptogcry_hash_abort(IESYS_CRYPTO_CONTEXT_BLOB **context);

#define iesys_crypto_hash_start iesys_cryptogcry_hash_start
#define iesys_crypto_hash_update iesys_cryptogcry_hash_update
#define iesys_crypto_hash_update2b iesys_cryptogcry_hash_update2b
#define iesys_crypto_hash_finish iesys_cryptogcry_hash_finish
#define iesys_crypto_hash_finish2b iesys_cryptogcry_hash_finish2b
#define iesys_crypto_hash_abort iesys_cryptogcry_hash_abort

TSS2_RC iesys_cryptogcry_hmac_start(
    IESYS_CRYPTO_CONTEXT_BLOB **context,
    TPM2_ALG_ID hmacAlg,
    const uint8_t *key,
    size_t size);

TSS2_RC iesys_cryptogcry_hmac_start2b(
    IESYS_CRYPTO_CONTEXT_BLOB **context,
    TPM2_ALG_ID hmacAlg,
    TPM2B *b);

TSS2_RC iesys_cryptogcry_hmac_update(
    IESYS_CRYPTO_CONTEXT_BLOB *context,
    const uint8_t *buffer,
    size_t size);

TSS2_RC iesys_cryptogcry_hmac_update2b(
    IESYS_CRYPTO_CONTEXT_BLOB *context,
    TPM2B *b);

TSS2_RC iesys_cryptogcry_hmac_finish(
    IESYS_CRYPTO_CONTEXT_BLOB **context,
    uint8_t *buffer,
    size_t *size);

TSS2_RC iesys_cryptogcry_hmac_finish2b(
    IESYS_CRYPTO_CONTEXT_BLOB **context,
    TPM2B *b);

void iesys_cryptogcry_hmac_abort(IESYS_CRYPTO_CONTEXT_BLOB **context);

#define iesys_crypto_hmac_start iesys_cryptogcry_hmac_start
#define iesys_crypto_hmac_start2b iesys_cryptogcry_hmac_start2b
#define iesys_crypto_hmac_update iesys_cryptogcry_hmac_update
#define iesys_crypto_hmac_update2b iesys_cryptogcry_hmac_update2b
#define iesys_crypto_hmac_finish iesys_cryptogcry_hmac_finish
#define iesys_crypto_hmac_finish2b iesys_cryptogcry_hmac_finish2b
#define iesys_crypto_hmac_abort iesys_cryptogcry_hmac_abort

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

TSS2_RC iesys_cryptogcry_random2b(TPM2B_NONCE *nonce, size_t num_bytes);
#define iesys_crypto_random2b iesys_cryptogcry_random2b

TSS2_RC iesys_cryptogcry_pk_encrypt(
    TPM2B_PUBLIC *key,
    size_t in_size,
    BYTE *in_buffer,
    size_t max_out_size,
    BYTE *out_buffer,
    size_t *out_size,
    const char *label);

#define iesys_crypto_pk_encrypt iesys_cryptogcry_pk_encrypt


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
    BYTE  *outKey);

TSS2_RC iesys_cryptogcry_sym_aes_encrypt(
    uint8_t *key,
    TPM2_ALG_ID tpm_sym_alg,
    TPMI_AES_KEY_BITS key_bits,
    TPM2_ALG_ID tpm_mode,
    size_t blk_len,
    uint8_t *dst,
    size_t dst_size,
    uint8_t *iv,
    size_t iv_len);

TSS2_RC iesys_cryptogcry_sym_aes_decrypt(
    uint8_t *key,
    TPM2_ALG_ID tpm_sym_alg,
    TPMI_AES_KEY_BITS key_bits,
    TPM2_ALG_ID tpm_mode,
    size_t blk_len,
    uint8_t *dst,
    size_t dst_size,
    uint8_t *iv,
    size_t iv_len);


#define iesys_crypto_sym_aes_encrypt iesys_cryptogcry_sym_aes_encrypt
#define iesys_crypto_sym_aes_decrypt iesys_cryptogcry_sym_aes_decrypt

/* @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ESYS_CRYPTO_H */
