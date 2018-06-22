/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef ESYS_CRYPTO_GCRYPT_H
#define ESYS_CRYPTO_GCRYPT_H

#include <stddef.h>
#include "tss2_tpm2_types.h"
#include "tss2-sys/sysapi_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _IESYS_CRYPTO_CONTEXT IESYS_CRYPTO_CONTEXT_BLOB;

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

TSS2_RC iesys_cryptogcry_sym_aes_encrypt(
    uint8_t *key,
    TPM2_ALG_ID tpm_sym_alg,
    TPMI_AES_KEY_BITS key_bits,
    TPM2_ALG_ID tpm_mode,
    size_t blk_len,
    uint8_t *dst,
    size_t dst_size,
    uint8_t *iv);

TSS2_RC iesys_cryptogcry_sym_aes_decrypt(
    uint8_t *key,
    TPM2_ALG_ID tpm_sym_alg,
    TPMI_AES_KEY_BITS key_bits,
    TPM2_ALG_ID tpm_mode,
    size_t blk_len,
    uint8_t *dst,
    size_t dst_size,
    uint8_t *iv);

TSS2_RC iesys_cryptogcry_get_ecdh_point(
    TPM2B_PUBLIC *key,
    size_t max_out_size,
    TPM2B_ECC_PARAMETER *Z,
    TPMS_ECC_POINT *Q,
    BYTE * out_buffer,
    size_t * out_size);

#define iesys_crypto_get_ecdh_point iesys_cryptogcry_get_ecdh_point
#define iesys_crypto_sym_aes_encrypt iesys_cryptogcry_sym_aes_encrypt
#define iesys_crypto_sym_aes_decrypt iesys_cryptogcry_sym_aes_decrypt

#endif /* ESYS_CRYPTO_GCRYPT_H */

#ifdef __cplusplus
} /* extern "C" */
#endif
