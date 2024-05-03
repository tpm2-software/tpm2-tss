/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/
#ifndef ESYS_CRYPTO_OSSL_H
#define ESYS_CRYPTO_OSSL_H

#ifdef HAVE_CONFIG_H
#include "config.h"           // for HAVE_EVP_SM4_CFB
#endif

#include <stddef.h>           // for NULL, size_t
#include <stdint.h>           // for uint8_t

#include "tss2_common.h"      // for TSS2_RC, BYTE
#include "tss2_esys.h"        // for ESYS_CRYPTO_CONTEXT_BLOB
#include "tss2_tpm2_types.h"  // for TPM2_ALG_ID, TPM2B_PUBLIC, TPMI_AES_KEY...

#ifdef __cplusplus
extern "C" {
#endif

#define OSSL_FREE(S,TYPE) if((S) != NULL) {TYPE##_free((void*) (S)); (S)=NULL;}

TSS2_RC iesys_cryptossl_hash_start(
    ESYS_CRYPTO_CONTEXT_BLOB **context,
    TPM2_ALG_ID hashAlg,
    void *userdata);

TSS2_RC iesys_cryptossl_hash_update(
    ESYS_CRYPTO_CONTEXT_BLOB *context,
    const uint8_t *buffer, size_t size,
    void *userdata);

TSS2_RC iesys_cryptossl_hash_finish(
    ESYS_CRYPTO_CONTEXT_BLOB **context,
    uint8_t *buffer,
    size_t *size,
    void *userdata);

void iesys_cryptossl_hash_abort(
    ESYS_CRYPTO_CONTEXT_BLOB **context,
    void *userdata);

#define iesys_crypto_rsa_pk_encrypt_internal iesys_cryptossl_pk_encrypt
#define iesys_crypto_hash_start_internal iesys_cryptossl_hash_start
#define iesys_crypto_hash_update_internal iesys_cryptossl_hash_update
#define iesys_crypto_hash_finish_internal iesys_cryptossl_hash_finish
#define iesys_crypto_hash_abort_internal iesys_cryptossl_hash_abort

TSS2_RC iesys_cryptossl_hmac_start(
    ESYS_CRYPTO_CONTEXT_BLOB **context,
    TPM2_ALG_ID hmacAlg,
    const uint8_t *key,
    size_t size,
    void *userdata);

TSS2_RC iesys_cryptossl_hmac_update(
    ESYS_CRYPTO_CONTEXT_BLOB *context,
    const uint8_t *buffer,
    size_t size,
    void *userdata);

TSS2_RC iesys_cryptossl_hmac_finish(
    ESYS_CRYPTO_CONTEXT_BLOB **context,
    uint8_t *buffer,
    size_t *size,
    void *userdata);

void iesys_cryptossl_hmac_abort(
    ESYS_CRYPTO_CONTEXT_BLOB **context,
    void *userdata);

#define iesys_crypto_hmac_start_internal iesys_cryptossl_hmac_start
#define iesys_crypto_hmac_start2b_internal iesys_cryptossl_hmac_start2b
#define iesys_crypto_hmac_update_internal iesys_cryptossl_hmac_update
#define iesys_crypto_hmac_update2b_internal iesys_cryptossl_hmac_update2b
#define iesys_crypto_hmac_finish_internal iesys_cryptossl_hmac_finish
#define iesys_crypto_hmac_finish2b_internal iesys_cryptossl_hmac_finish2b
#define iesys_crypto_hmac_abort_internal iesys_cryptossl_hmac_abort

TSS2_RC iesys_cryptossl_random2b(
    TPM2B_NONCE *nonce,
    size_t num_bytes,
    void *userdata);

TSS2_RC iesys_cryptossl_pk_encrypt(
    TPM2B_PUBLIC *key,
    size_t in_size,
    BYTE *in_buffer,
    size_t max_out_size,
    BYTE *out_buffer,
    size_t *out_size,
    const char *label,
    void *userdata);


TSS2_RC iesys_cryptossl_sym_aes_encrypt(
    uint8_t *key,
    TPM2_ALG_ID tpm_sym_alg,
    TPMI_AES_KEY_BITS key_bits,
    TPM2_ALG_ID tpm_mode,
    uint8_t *dst,
    size_t dst_size,
    uint8_t *iv,
    void *userdata);

TSS2_RC iesys_cryptossl_sym_aes_decrypt(
    uint8_t *key,
    TPM2_ALG_ID tpm_sym_alg,
    TPMI_AES_KEY_BITS key_bits,
    TPM2_ALG_ID tpm_mode,
    uint8_t *dst,
    size_t dst_size,
    uint8_t *iv,
    void *userdata);

#if HAVE_EVP_SM4_CFB && !defined(OPENSSL_NO_SM4)
TSS2_RC iesys_cryptossl_sym_sm4_encrypt(
    uint8_t *key,
    TPM2_ALG_ID tpm_sym_alg,
    TPMI_SM4_KEY_BITS key_bits,
    TPM2_ALG_ID tpm_mode,
    uint8_t *dst,
    size_t dst_size,
    uint8_t *iv,
    void *userdata);

TSS2_RC iesys_cryptossl_sym_sm4_decrypt(
    uint8_t *key,
    TPM2_ALG_ID tpm_sym_alg,
    TPMI_SM4_KEY_BITS key_bits,
    TPM2_ALG_ID tpm_mode,
    uint8_t *dst,
    size_t dst_size,
    uint8_t *iv,
    void *userdata);
#endif

TSS2_RC iesys_cryptossl_get_ecdh_point(
    TPM2B_PUBLIC *key,
    size_t max_out_size,
    TPM2B_ECC_PARAMETER *Z,
    TPMS_ECC_POINT *Q,
    BYTE * out_buffer,
    size_t * out_size,
    void *userdata);

#define iesys_crypto_get_random2b_internal iesys_cryptossl_random2b
#define iesys_crypto_get_ecdh_point_internal iesys_cryptossl_get_ecdh_point
#define iesys_crypto_aes_encrypt_internal iesys_cryptossl_sym_aes_encrypt
#define iesys_crypto_aes_decrypt_internal iesys_cryptossl_sym_aes_decrypt
#if HAVE_EVP_SM4_CFB && !defined(OPENSSL_NO_SM4)
#define iesys_crypto_sm4_encrypt_internal iesys_cryptossl_sym_sm4_encrypt
#define iesys_crypto_sm4_decrypt_internal iesys_cryptossl_sym_sm4_decrypt
#else
#define iesys_crypto_sm4_encrypt_internal NULL
#define iesys_crypto_sm4_decrypt_internal NULL
#endif

TSS2_RC iesys_cryptossl_init(void *userdata);

#define iesys_crypto_init_internal iesys_cryptossl_init

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ESYS_CRYPTO_OSSL_H */
