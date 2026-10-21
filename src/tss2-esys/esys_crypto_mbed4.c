/* SPDX-FileCopyrightText: 2020, Andreas Droescher */
/* SPDX-FileCopyrightText: 2026, Yegor Yefremov */
/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * ESYS crypto backend for Mbed TLS 4.x.
 *
 * Mbed TLS 4.x moved the crypto code to TF-PSA-Crypto. Its low-level APIs
 * (RSA, ECDH, AES, DRBG, HMAC via md.h) are private, so this backend uses
 * the PSA Crypto API for them. Hashing via md.h is still public.
 * Mbed TLS 2.x and 3.x are handled by esys_crypto_mbed.c.
 */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>
#include <string.h>

#include <mbedtls/asn1write.h>
#include <mbedtls/md.h>
#include <mbedtls/psa_util.h>
#include <psa/crypto.h>

#include "tss2_esys.h"
#include "tss2_mu.h"
#include "util/aux_util.h"

#define LOGMODULE esys_crypto
#include "util/log.h"

/** Context to hold temporary values for iesys_crypto */
typedef struct ESYS_CRYPTO_CONTEXT_BLOB {
    enum {
        IESYS_CRYPTMBED_TYPE_HASH = 1,
        IESYS_CRYPTMBED_TYPE_HMAC,
    } type; /**< The type of context to hold; hash or hmac */
    union {
        struct {
            mbedtls_md_context_t mbed_context;
            size_t               hash_len;
        } hash; /**< the state variables for a hash context */
        struct {
            psa_mac_operation_t operation;
            psa_key_id_t        key_id;
            size_t              hmac_len;
        } hmac; /**< the state variables for an hmac context */
    };
} IESYS_CRYPTMBED_CONTEXT;

/** Map a TPM hash algorithm to an Mbed TLS message digest type.
 *
 * @param[in] hashAlg The TPM hash algorithm.
 * @retval The message digest type or MBEDTLS_MD_NONE if unsupported.
 */
static mbedtls_md_type_t
get_md_type(TPM2_ALG_ID hashAlg) {
    switch (hashAlg) {
    case TPM2_ALG_SHA1:
        return MBEDTLS_MD_SHA1;
    case TPM2_ALG_SHA256:
        return MBEDTLS_MD_SHA256;
    case TPM2_ALG_SHA384:
        return MBEDTLS_MD_SHA384;
    case TPM2_ALG_SHA512:
        return MBEDTLS_MD_SHA512;
    default:
        return MBEDTLS_MD_NONE;
    }
}

/** Get the key size of a NIST prime curve (PSA_ECC_FAMILY_SECP_R1).
 *
 * @param[in] curve The TPM curve ID.
 * @retval The key size in bits or 0 if unsupported.
 */
static size_t
get_ecc_key_bits(TPMI_ECC_CURVE curve) {
    switch (curve) {
    case TPM2_ECC_NIST_P192:
        return 192;
    case TPM2_ECC_NIST_P224:
        return 224;
    case TPM2_ECC_NIST_P256:
        return 256;
    case TPM2_ECC_NIST_P384:
        return 384;
    case TPM2_ECC_NIST_P521:
        return 521;
    default:
        return 0;
    }
}

/** Write an RSA public key in the DER format (RSAPublicKey) used by PSA.
 *
 * Like the mbedtls_asn1_write_*() functions, this writes backwards from *p
 * towards start.
 * @param[in,out] p The current position in the buffer, set to the start of
 *                the DER encoding on success.
 * @param[in] start The start of the buffer.
 * @param[in] n The modulus in big-endian format.
 * @param[in] n_size The size of the modulus.
 * @param[in] e The public exponent in big-endian format.
 * @param[in] e_size The size of the public exponent.
 * @retval The length of the DER encoding on success.
 * @retval A negative Mbed TLS error code on failure.
 */
static int
write_rsa_pub(uint8_t      **p,
              uint8_t       *start,
              const uint8_t *n,
              size_t         n_size,
              const uint8_t *e,
              size_t         e_size) {
    int    ret;
    size_t len = 0;

    /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_integer(p, start, e, e_size));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_integer(p, start, n, n_size));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(
        len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return (int)len;
}

/** Provide the context for the computation of a hash digest.
 *
 * The context will be created and initialized according to the hash function.
 * @param[out] context The created context (callee-allocated).
 * @param[in] hashAlg The hash algorithm for the creation of the context.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE or TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_ESYS_RC_MEMORY Memory cannot be allocated.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptmbed_hash_start(ESYS_CRYPTO_CONTEXT_BLOB **context,
                           TPM2_ALG_ID                hashAlg,
                           void                      *userdata) {
    UNUSED(userdata);

    TSS2_RC                  r = TSS2_RC_SUCCESS;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(get_md_type(hashAlg));

    if (context == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed in for context");
    }
    IESYS_CRYPTMBED_CONTEXT *mycontext = calloc(1, sizeof(IESYS_CRYPTMBED_CONTEXT));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);

    mbedtls_md_init(&mycontext->hash.mbed_context);

    if (md_info == NULL) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED, "Unsupported hash algorithm (%" PRIu16 ")",
                   cleanup, hashAlg);
    }

    mycontext->hash.hash_len = mbedtls_md_get_size(md_info);

    if (mbedtls_md_setup(&mycontext->hash.mbed_context, md_info, 0) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "MBED HASH setup", cleanup);
    }

    if (mbedtls_md_starts(&mycontext->hash.mbed_context) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "MBED HASH start", cleanup);
    }

    mycontext->type = IESYS_CRYPTMBED_TYPE_HASH;

    *context = (ESYS_CRYPTO_CONTEXT_BLOB *)mycontext;

    return TSS2_RC_SUCCESS;

cleanup:
    mbedtls_md_free(&mycontext->hash.mbed_context);
    SAFE_FREE(mycontext);
    return r;
}

/** Update the digest value of a digest object from a byte buffer.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm of the context. <
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] buffer The data for the update.
 * @param[in] size The size of the data buffer.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 */
TSS2_RC
iesys_cryptmbed_hash_update(ESYS_CRYPTO_CONTEXT_BLOB *context,
                            const uint8_t            *buffer,
                            size_t                    size,
                            void                     *userdata) {
    UNUSED(userdata);

    if (context == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTMBED_CONTEXT *mycontext = (IESYS_CRYPTMBED_CONTEXT *)context;
    if (mycontext->type != IESYS_CRYPTMBED_TYPE_HASH) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    if (mbedtls_md_update(&mycontext->hash.mbed_context, buffer, size) != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "MBED HASH update");
    }

    return TSS2_RC_SUCCESS;
}

/** Get the digest value of a digest object and close the context.
 *
 * The digest value will written to a passed buffer and the resources of the
 * digest object are released.
 * @param[in,out] context The context of the digest object to be released
 * @param[out] buffer The buffer for the digest value (caller-allocated).
 * @param[out] size The size of the digest.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptmbed_hash_finish(ESYS_CRYPTO_CONTEXT_BLOB **context,
                            uint8_t                   *buffer,
                            size_t                    *size,
                            void                      *userdata) {
    UNUSED(userdata);

    TSS2_RC r = TSS2_RC_SUCCESS;

    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTMBED_CONTEXT *mycontext = (IESYS_CRYPTMBED_CONTEXT *)*context;
    if (mycontext->type != IESYS_CRYPTMBED_TYPE_HASH) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    if (*size < mycontext->hash.hash_len) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "Buffer too small");
    }

    if (mbedtls_md_finish(&mycontext->hash.mbed_context, buffer) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "MBED HASH finish", cleanup);
    }

    *size = mycontext->hash.hash_len;

cleanup:
    mbedtls_md_free(&mycontext->hash.mbed_context);
    SAFE_FREE(mycontext);
    *context = NULL;

    return r;
}

/** Release the resources of a digest object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the digest object.
 */
void
iesys_cryptmbed_hash_abort(ESYS_CRYPTO_CONTEXT_BLOB **context, void *userdata) {
    UNUSED(userdata);

    if (context == NULL || *context == NULL) {
        return;
    }

    IESYS_CRYPTMBED_CONTEXT *mycontext = (IESYS_CRYPTMBED_CONTEXT *)*context;
    if (mycontext->type != IESYS_CRYPTMBED_TYPE_HASH) {
        return;
    }

    mbedtls_md_free(&mycontext->hash.mbed_context);
    free(mycontext);
    *context = NULL;
}

/* HMAC */

/** Release the crypto library resources of an HMAC context.
 *
 * @param[in,out] mycontext The HMAC context.
 */
static void
hmac_free(IESYS_CRYPTMBED_CONTEXT *mycontext) {
    psa_mac_abort(&mycontext->hmac.operation);
    psa_destroy_key(mycontext->hmac.key_id);
}

/** Provide the context an HMAC digest object from a byte buffer key.
 *
 * The context will be created and initialized according to the hash function
 * and the used HMAC key.
 * @param[out] context The created context (callee-allocated).
 * @param[in] hmacAlg The hash algorithm for the HMAC computation.
 * @param[in] key The byte buffer of the HMAC key.
 * @param[in] size The size of the HMAC key.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_ESYS_RC_MEMORY Memory cannot be allocated.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptmbed_hmac_start(ESYS_CRYPTO_CONTEXT_BLOB **context,
                           TPM2_ALG_ID                hashAlg,
                           const uint8_t             *key,
                           size_t                     size,
                           void                      *userdata) {
    UNUSED(userdata);

    TSS2_RC                  r = TSS2_RC_SUCCESS;
    mbedtls_md_type_t        md_type = get_md_type(hashAlg);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    psa_algorithm_t          alg = PSA_ALG_HMAC(mbedtls_md_psa_alg_from_type(md_type));
    psa_key_attributes_t     attributes = PSA_KEY_ATTRIBUTES_INIT;
    /* PSA rejects empty keys; HMAC pads the key with zeros, so use one zero byte */
    const uint8_t zero_key = 0;

    if (context == NULL || key == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed in for context");
    }
    IESYS_CRYPTMBED_CONTEXT *mycontext = calloc(1, sizeof(IESYS_CRYPTMBED_CONTEXT));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);

    mycontext->hmac.operation = psa_mac_operation_init();
    mycontext->hmac.key_id = PSA_KEY_ID_NULL;

    if (md_info == NULL) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED, "Unsupported hash algorithm (%" PRIu16 ")",
                   cleanup, hashAlg);
    }

    mycontext->hmac.hmac_len = mbedtls_md_get_size(md_info);

    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, alg);

    if (psa_import_key(&attributes, size ? key : &zero_key, size ? size : 1,
                       &mycontext->hmac.key_id)
        != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "MBED HMAC setup", cleanup);
    }

    if (psa_mac_sign_setup(&mycontext->hmac.operation, mycontext->hmac.key_id, alg)
        != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "MBED HMAC start", cleanup);
    }

    mycontext->type = IESYS_CRYPTMBED_TYPE_HMAC;

    *context = (ESYS_CRYPTO_CONTEXT_BLOB *)mycontext;

    return TSS2_RC_SUCCESS;

cleanup:
    hmac_free(mycontext);
    SAFE_FREE(mycontext);
    return r;
}

/** Update and HMAC digest value from a byte buffer.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm and the key of the context.
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] buffer The data for the update.
 * @param[in] size The size of the data buffer.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 */
TSS2_RC
iesys_cryptmbed_hmac_update(ESYS_CRYPTO_CONTEXT_BLOB *context,
                            const uint8_t            *buffer,
                            size_t                    size,
                            void                     *userdata) {
    UNUSED(userdata);

    if (context == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTMBED_CONTEXT *mycontext = (IESYS_CRYPTMBED_CONTEXT *)context;
    if (mycontext->type != IESYS_CRYPTMBED_TYPE_HMAC) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    if (psa_mac_update(&mycontext->hmac.operation, buffer, size) != PSA_SUCCESS) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "MBED HMAC update");
    }

    return TSS2_RC_SUCCESS;
}

/** Write the HMAC digest value to a byte buffer and close the context.
 *
 * The digest value will written to a passed buffer and the resources of the
 * HMAC object are released.
 * @param[in,out] context The context of the HMAC object.
 * @param[out] buffer The buffer for the digest value (caller-allocated).
 * @param[out] size The size of the digest.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_SIZE If the size passed is lower than the HMAC length.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptmbed_hmac_finish(ESYS_CRYPTO_CONTEXT_BLOB **context,
                            uint8_t                   *buffer,
                            size_t                    *size,
                            void                      *userdata) {
    UNUSED(userdata);

    TSS2_RC r = TSS2_RC_SUCCESS;

    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTMBED_CONTEXT *mycontext = (IESYS_CRYPTMBED_CONTEXT *)*context;
    if (mycontext->type != IESYS_CRYPTMBED_TYPE_HMAC) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    if (*size < mycontext->hmac.hmac_len) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "Buffer too small");
    }

    if (psa_mac_sign_finish(&mycontext->hmac.operation, buffer, *size, size) != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "MBED HMAC finish", cleanup);
    }

    *size = mycontext->hmac.hmac_len;

cleanup:
    hmac_free(mycontext);
    SAFE_FREE(mycontext);
    *context = NULL;
    return r;
}

/** Release the resources of an HAMC object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the HMAC object.
 */
void
iesys_cryptmbed_hmac_abort(ESYS_CRYPTO_CONTEXT_BLOB **context, void *userdata) {
    UNUSED(userdata);

    if (context == NULL || *context == NULL) {
        return;
    }

    IESYS_CRYPTMBED_CONTEXT *mycontext = (IESYS_CRYPTMBED_CONTEXT *)*context;
    if (mycontext->type != IESYS_CRYPTMBED_TYPE_HMAC) {
        return;
    }

    hmac_free(mycontext);
    free(mycontext);
    *context = NULL;
}

/** Compute random TPM2B data.
 *
 * The random data will be generated and written to a passed TPM2B structure.
 * @param[out] nonce The TPM2B structure for the random data (caller-allocated).
 * @param[in] num_bytes The number of bytes to be generated.
 * @retval TSS2_RC_SUCCESS on success.
 *
 * NOTE: the TPM should not be used to obtain the random data
 */
TSS2_RC
iesys_cryptmbed_random2b(TPM2B_NONCE *nonce, size_t num_bytes, void *userdata) {
    UNUSED(userdata);

    if (num_bytes == 0) {
        nonce->size = sizeof(nonce->buffer);
    } else {
        nonce->size = num_bytes;
    }

    if (psa_generate_random(&nonce->buffer[0], nonce->size) != PSA_SUCCESS) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "Hash algorithm not supported");
    }

    return TSS2_RC_SUCCESS;
}

/** Encryption of a buffer using a public (RSA) key.
 *
 * Encrypting a buffer using a public key is used for example during
 * Esys_StartAuthSession in order to encrypt the salt value.
 * @param[in] key The key to be used for encryption.
 * @param[in] in_size The size of the buffer to be encrypted.
 * @param[in] in_buffer The data buffer to be encrypted.
 * @param[in] max_out_size The maximum size for the output encrypted buffer.
 * @param[out] out_buffer The encrypted buffer.
 * @param[out] out_size The size of the encrypted output.
 * @param[in] label The label used in the encryption scheme.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_ESYS_RC_BAD_VALUE The algorithm of key is not implemented.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE The internal crypto engine failed.
 */
TSS2_RC
iesys_cryptmbed_pk_encrypt(TPM2B_PUBLIC *pub_tpm_key,
                           size_t        in_size,
                           BYTE         *in_buffer,
                           size_t        max_out_size,
                           BYTE         *out_buffer,
                           size_t       *out_size,
                           const char   *label,
                           void         *userdata) {
    UNUSED(userdata);

    TSS2_RC              r = TSS2_RC_SUCCESS;
    mbedtls_md_type_t    hash_id = get_md_type(pub_tpm_key->publicArea.nameAlg);
    psa_algorithm_t      alg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t         key_id = PSA_KEY_ID_NULL;
    const uint8_t       *salt = NULL;
    size_t               salt_len = 0;
    uint8_t              der[TPM2_MAX_RSA_KEY_BYTES + 32];
    uint8_t             *der_start = &der[sizeof(der)];
    int                  der_len;

    if (hash_id == MBEDTLS_MD_NONE) {
        return_error(TSS2_ESYS_RC_NOT_IMPLEMENTED, "Hash algorithm not supported");
    }

    if (pub_tpm_key->publicArea.unique.rsa.size == 0) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "Public key size may not be 0");
    }

    UINT8  exp[sizeof(UINT32)] = { 0x00, 0x01, 0x00, 0x01 }; // big-endian 65537
    UINT32 exp_as_int = pub_tpm_key->publicArea.parameters.rsaDetail.exponent;
    if (exp_as_int != 0) {
        exp[0] = (exp_as_int >> 24) & 0xff;
        exp[1] = (exp_as_int >> 16) & 0xff;
        exp[2] = (exp_as_int >> 8) & 0xff;
        exp[3] = (exp_as_int >> 0) & 0xff;
    }

    switch (pub_tpm_key->publicArea.parameters.rsaDetail.scheme.scheme) {
    case TPM2_ALG_RSAES:
        alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
        break;
    case TPM2_ALG_OAEP:
        alg = PSA_ALG_RSA_OAEP(mbedtls_md_psa_alg_from_type(hash_id));
        salt = (const uint8_t *)label;
        salt_len = strlen(label) + 1;
        break;
    default:
        return_error(TSS2_ESYS_RC_BAD_VALUE, "Illegal RSA scheme");
    }

    der_len = write_rsa_pub(&der_start, &der[0], pub_tpm_key->publicArea.unique.rsa.buffer,
                            pub_tpm_key->publicArea.unique.rsa.size, &exp[0], sizeof(UINT32));
    if (der_len < 0) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "Could not convert public key");
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);

    if (psa_import_key(&attributes, der_start, der_len, &key_id) != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Could not import public key", cleanup);
    }

    if (psa_get_key_attributes(key_id, &attributes) != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Could not get key attributes", cleanup);
    }

    if (PSA_BITS_TO_BYTES(psa_get_key_bits(&attributes)) > max_out_size) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Encrypted data too big", cleanup);
    }

    if (psa_asymmetric_encrypt(key_id, alg, in_buffer, in_size, salt, salt_len, out_buffer,
                               max_out_size, out_size)
        != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Could not encrypt data.", cleanup);
    }

cleanup:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key_id);
    return r;
}

/** Computation of ephemeral ECC key and shared secret Z.
 *
 * According to the description in TPM spec part 1 C 6.1 a shared secret
 * between application and TPM is computed (ECDH). An ephemeral ECC key and a
 * TPM key are used for the ECDH key exchange.
 * @param[in] key The key to be used for ECDH key exchange.
 * @param[in] max_out_size the max size for the output of the public key of the
 *            computed ephemeral key.
 * @param[out] Z The computed shared secret.
 * @param[out] Q The public part of the ephemeral key in TPM format.
 * @param[out] out_buffer The public part of the ephemeral key will be marshaled
 *             to this buffer.
 * @param[out] out_size The size of the marshaled output.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_ESYS_RC_BAD_VALUE The algorithm of key is not implemented.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE The internal crypto engine failed.
 */
TSS2_RC
iesys_cryptmbed_get_ecdh_point(TPM2B_PUBLIC        *key,
                               size_t               max_out_size,
                               TPM2B_ECC_PARAMETER *Z,
                               TPMS_ECC_POINT      *Q,
                               BYTE                *out_buffer,
                               size_t              *out_size,
                               void                *userdata) {
    UNUSED(userdata);

    TSS2_RC              r = TSS2_RC_SUCCESS;
    psa_status_t         status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t         key_id = PSA_KEY_ID_NULL;
    /* Points in uncompressed format: 0x04 || x || y */
    uint8_t pub[1 + 2 * TPM2_MAX_ECC_KEY_BYTES];
    uint8_t peer[1 + 2 * TPM2_MAX_ECC_KEY_BYTES] = { 0 };
    size_t  pub_len;
    size_t  z_len;
    size_t  key_bits = get_ecc_key_bits(key->publicArea.parameters.eccDetail.curveID);
    size_t  key_size = PSA_BITS_TO_BYTES(key_bits);

    if (key_bits == 0) {
        return_error(TSS2_ESYS_RC_NOT_IMPLEMENTED, "ECC curve not implemented.");
    }

    /* Generate ephemeral key */
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);

    status = psa_generate_key(&attributes, &key_id);
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED, "ECC curve not implemented.", cleanup);
    } else if (status != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "ECDH gen failed", cleanup);
    }

    /* Write affine coordinates of ephemeral pub key to TPM point Q */
    if (psa_export_public_key(key_id, &pub[0], sizeof(pub), &pub_len) != PSA_SUCCESS
        || pub_len != 1 + 2 * key_size) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Export of ephemeral pub key failed", cleanup);
    }
    memcpy(&Q->x.buffer[0], &pub[1], key_size);
    Q->x.size = key_size;
    memcpy(&Q->y.buffer[0], &pub[1 + key_size], key_size);
    Q->y.size = key_size;

    /* Read pub key from TPM as an uncompressed point, padded to the curve size */
    if (key->publicArea.unique.ecc.x.size > key_size
        || key->publicArea.unique.ecc.y.size > key_size) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Point Qp is invalid", cleanup);
    }
    peer[0] = 0x04;
    memcpy(&peer[1 + key_size - key->publicArea.unique.ecc.x.size],
           &key->publicArea.unique.ecc.x.buffer[0], key->publicArea.unique.ecc.x.size);
    memcpy(&peer[1 + 2 * key_size - key->publicArea.unique.ecc.y.size],
           &key->publicArea.unique.ecc.y.buffer[0], key->publicArea.unique.ecc.y.size);

    /* Calculate shared secret and write it to TPM ECC param Z. This also
     * validates TPM's pub key */
    if (psa_raw_key_agreement(PSA_ALG_ECDH, key_id, &peer[0], 1 + 2 * key_size, &Z->buffer[0],
                              sizeof(Z->buffer), &z_len)
        != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "ECDH compute shared failed", cleanup);
    }
    Z->size = z_len;

    /* Write the public ephemeral key in TPM format to out buffer */
    size_t offset = 0;
    r = Tss2_MU_TPMS_ECC_POINT_Marshal(Q, &out_buffer[0], max_out_size, &offset);
    goto_if_error(r, "Error marshaling Q", cleanup);
    *out_size = offset;

cleanup:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key_id);
    return r;
}

/** Encrypt or decrypt data with AES in CFB mode.
 *
 * @param[in] encrypt true to encrypt, false to decrypt.
 * @param[in] key key used for AES.
 * @param[in] key_bits Key size in bits.
 * @param[in,out] buffer Data to be processed. The result will be stored in
 *                this buffer.
 * @param[in] buffer_size size of the data.
 * @param[in] iv The initialization vector.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE if the key size is not supported.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
static TSS2_RC
sym_aes_cfb(bool              encrypt,
            uint8_t          *key,
            TPMI_AES_KEY_BITS key_bits,
            uint8_t          *buffer,
            size_t            buffer_size,
            uint8_t          *iv) {
    TSS2_RC                r = TSS2_RC_SUCCESS;
    psa_status_t           status;
    psa_key_attributes_t   attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t           key_id = PSA_KEY_ID_NULL;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    size_t                 update_len = 0;
    size_t                 finish_len = 0;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_usage_flags(&attributes, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CFB);

    if (psa_import_key(&attributes, key, PSA_BITS_TO_BYTES(key_bits), &key_id) != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE, "Key size not implemented.", cleanup);
    }

    if (encrypt) {
        status = psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_CFB);
    } else {
        status = psa_cipher_decrypt_setup(&operation, key_id, PSA_ALG_CFB);
    }
    if (status != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "AES setup", cleanup);
    }

    if (psa_cipher_set_iv(&operation, iv, PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES))
        != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "AES set IV", cleanup);
    }

    /* CFB does not change the data size, so the buffer can be processed in place */
    if (psa_cipher_update(&operation, buffer, buffer_size, buffer, buffer_size, &update_len)
        != PSA_SUCCESS) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "AES CFB update", cleanup);
    }

    if (psa_cipher_finish(&operation, &buffer[update_len], buffer_size - update_len, &finish_len)
            != PSA_SUCCESS
        || update_len + finish_len != buffer_size) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "AES CFB finish", cleanup);
    }

cleanup:
    psa_cipher_abort(&operation);
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key_id);
    return r;
}

/** Encrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be encrypted. The encrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @retval TSS2_RC_SUCCESS on success, or TSS2_ESYS_RC_BAD_VALUE and
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters,
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptmbed_sym_aes_encrypt(uint8_t          *key,
                                TPM2_ALG_ID       tpm_sym_alg,
                                TPMI_AES_KEY_BITS key_bits,
                                TPM2_ALG_ID       tpm_mode,
                                uint8_t          *buffer,
                                size_t            buffer_size,
                                uint8_t          *iv,
                                void             *userdata) {
    UNUSED(userdata);

    if (key == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Bad reference");
    }

    if (tpm_sym_alg != TPM2_ALG_AES || tpm_mode != TPM2_ALG_CFB) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "AES encrypt called with wrong algorithm.");
    }

    return sym_aes_cfb(true, key, key_bits, buffer, buffer_size, iv);
}

/** Decrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be decrypted. The decrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @retval TSS2_RC_SUCCESS on success, or TSS2_ESYS_RC_BAD_VALUE and
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters,
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptmbed_sym_aes_decrypt(uint8_t          *key,
                                TPM2_ALG_ID       tpm_sym_alg,
                                TPMI_AES_KEY_BITS key_bits,
                                TPM2_ALG_ID       tpm_mode,
                                uint8_t          *buffer,
                                size_t            buffer_size,
                                uint8_t          *iv,
                                void             *userdata) {
    UNUSED(userdata);

    if (key == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Bad reference");
    }

    if (tpm_sym_alg != TPM2_ALG_AES || tpm_mode != TPM2_ALG_CFB) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "AES decrypt called with wrong algorithm.");
    }

    return sym_aes_cfb(false, key, key_bits, buffer, buffer_size, iv);
}

TSS2_RC
iesys_cryptmbed_init(void *userdata) {
    UNUSED(userdata);

    if (psa_crypto_init() != PSA_SUCCESS) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "PSA crypto init failed");
    }

    return TSS2_RC_SUCCESS;
}
