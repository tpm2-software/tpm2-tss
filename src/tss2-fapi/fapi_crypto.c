/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // for HAVE_EVP_SM3
#endif

#include <inttypes.h>         // for PRIu16
#include <openssl/bio.h>      // for BIO_free, BIO_new_mem_buf, BIO_free...
#include <openssl/bn.h>       // for BN_free, BN_bin2bn, BN_bn2bin, BN_b...
#include <openssl/buffer.h>   // for buf_mem_st
#include <openssl/crypto.h>   // for OSSL_LIB_CTX_free, OSSL_LIB_CTX_new
#include <openssl/ec.h>       // for ECDSA_SIG_free, i2d_ECDSA_SIG, ECDS...
#include <openssl/evp.h>      // for EVP_PKEY_type, EVP_PKEY_free, EVP_PKEY
#include <openssl/obj_mac.h>  // for NID_sm2, NID_X9_62_prime192v1, NID_...
#include <openssl/objects.h>  // for OBJ_nid2sn, OBJ_txt2nid
#include <openssl/opensslv.h> // for OPENSSL_VERSION_NUMBER
#include <openssl/pem.h>      // for PEM_read_bio_PUBKEY, PEM_read_bio_P...
#include <openssl/rsa.h>      // for EVP_PKEY_CTX_set_rsa_padding, EVP_P...
#include <openssl/x509.h>     // for X509_free, X509_get_pubkey, d2i_X509
#include <stdbool.h>          // for bool, false, true
#include <stdio.h>            // for stderr
#include <stdlib.h>           // for malloc, calloc, free
#include <string.h>           // for memcpy, strlen, memset, strdup
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/aes.h>
#else
#include <openssl/core_names.h>  // for OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PK...
#include <openssl/param_build.h> // for OSSL_PARAM_BLD_free, OSSL_PARAM_BLD...
#include <openssl/params.h>      // for OSSL_PARAM_free
#endif
#include <openssl/err.h> // for ERR_print_errors_fp

#include "fapi_crypto.h"
#include "fapi_int.h"     // for OSSL_FREE, HASH_UPDATE_BUFFER
#include "ifapi_macros.h" // for goto_if_null2, check_oom
#include "tss2_crypto.h"  // for hash functions ....

#define LOGMODULE fapi
#include "util/log.h" // for return_if_null, goto_error, goto_if...

/**
 * Returns the signature scheme that is currently used in the FAPI context.
 *
 * @param[in] profile The FAPI profile from which the signing scheme is
 *            retrieved
 * @param[in] tpmPublic The public key for which the signing key is fetched
 *            from the FAPI
 * @param[out] signatureScheme The currently used signature scheme
 *
 * @retval TSS2_RC_SUCCESS if the signature scheme was successfully fetched
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if one of the parameters is NULL
 * @retval TSS2_FAPI_RC_BAD_VALUE if the key type is not TPM2_ALG_RSA or
 *         TPM2_ALG_ECC
 */
TPM2_RC
ifapi_get_profile_sig_scheme(const IFAPI_PROFILE *profile,
                             const TPMT_PUBLIC   *tpmPublic,
                             TPMT_SIG_SCHEME     *signatureScheme) {
    /* Check for NULL parameters */
    return_if_null(profile, "profile is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(tpmPublic, "tpmPublic is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signatureScheme, "signatureScheme is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Determine the appropriate signing scheme */
    if (tpmPublic->type == TPM2_ALG_RSA) {
        *signatureScheme = profile->rsa_signing_scheme;
        return TSS2_RC_SUCCESS;
    } else if (tpmPublic->type == TPM2_ALG_ECC) {
        *signatureScheme = profile->ecc_signing_scheme;
        return TSS2_RC_SUCCESS;
    } else {
        return_error(TSS2_FAPI_RC_BAD_VALUE, "Invalid key type.");
    }
}

/**
 * Returns a suitable openSSL RSA signature scheme identifiver for a given TSS
 * RSA signature scheme identifier.
 *
 * @param[in] signatureScheme The TSS RSA signature scheme identifier
 *
 * @retval RSA_PCKS1_PSS_PADDING if signatureScheme is TPM2_ALG_RSAPSS
 * @retval RSA_PKCS1_PADDING if signatureScheme is TPM2_ALG_RSASSA
 * @retval 0 otherwise
 */
static int
get_sig_scheme(TPM2_ALG_ID signatureScheme) {
    switch (signatureScheme) {
    case TPM2_ALG_RSAPSS:
        return RSA_PKCS1_PSS_PADDING;
    case TPM2_ALG_RSASSA:
        return RSA_PKCS1_PADDING;
    default:
        return 0;
    }
}

/**
 * Convert a TPM ECDSA signature into a DER formatted byte buffer. This can be
 * used by TLS libraries.
 *
 * @param[in]  tpmSignature The signature created by the TPM
 * @param[out] signature A byte buffer that will hold the DER representation of
 *             the signature  (callee allocated)
 * @param[out] signatureSize The size of signature in bytes. May be NULL
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if tpmSignature is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 */
TSS2_RC
ifapi_tpm_ecc_sig_to_der(const TPMT_SIGNATURE *tpmSignature,
                         uint8_t             **signature,
                         size_t               *signatureSize) {
    /* Check for NULL parameters */
    return_if_null(tpmSignature, "tpmSignature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    ECDSA_SIG *ecdsaSignature = NULL;
    BIGNUM    *bns = NULL, *bnr = NULL;
    int        osslRC;
    TSS2_RC    r;
    uint8_t   *signatureWalking;

    /* Initialize an OpenSSL ECDSA signature which servers as an intermediate
     * between the TSS ECDSA signature and the DER byte buffer */
    ecdsaSignature = ECDSA_SIG_new();
    goto_if_null(ecdsaSignature, "Out of memory", TSS2_FAPI_RC_MEMORY, cleanup);

    bns = BN_bin2bn(&tpmSignature->signature.ecdsa.signatureS.buffer[0],
                    tpmSignature->signature.ecdsa.signatureS.size, NULL);
    goto_if_null(bns, "Out of memory", TSS2_FAPI_RC_MEMORY, cleanup);

    bnr = BN_bin2bn(&tpmSignature->signature.ecdsa.signatureR.buffer[0],
                    tpmSignature->signature.ecdsa.signatureR.size, NULL);
    goto_if_null(bnr, "Out of memory", TSS2_FAPI_RC_MEMORY, cleanup);

    ECDSA_SIG_set0(ecdsaSignature, bnr, bns);

    osslRC = i2d_ECDSA_SIG(ecdsaSignature, NULL);
    if (osslRC == -1) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "OSSL error", cleanup);
    }

    /* Initialize the byte buffer for the DER representation */
    *signature = malloc(osslRC);
    goto_if_null(*signature, "Out of memory", TSS2_FAPI_RC_MEMORY, cleanup);

    signatureWalking = *signature;
    if (signatureSize != NULL) {
        *signatureSize = osslRC;
    }

    /* Convert the OpenSSL ECDSA signature to the DER buffer */
    osslRC = i2d_ECDSA_SIG(ecdsaSignature, &signatureWalking);
    if (!osslRC) {
        free(*signature);
        *signature = NULL;
        if (signatureSize != NULL) {
            *signatureSize = 0;
        }
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "OSSL error", cleanup);
    }
    r = TSS2_RC_SUCCESS;

cleanup:
    if (ecdsaSignature)
        ECDSA_SIG_free(ecdsaSignature);
    return r;
}

/**
 * Size of the table with the possible padding schemes
 */
#define N_PADDING 2

/**
 * Table with possible padding schemes to guess the one appropriate for
 * for RSA signature verification
 */
static const int rsaPadding[N_PADDING] = { RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING };
static TSS2_RC
rsa_evp_verify_signature(EVP_PKEY      *publicKey,
                         const uint8_t *signature,
                         size_t         signatureSize,
                         const EVP_MD  *mdType,
                         const uint8_t *digest,
                         size_t         digestSize) {
    TSS2_RC       r;
    EVP_PKEY_CTX *ctx = NULL;
    /* Try all possible padding schemes for verification */
    for (int i = 0; i < N_PADDING; i++) {
        ctx = EVP_PKEY_CTX_new(publicKey, NULL);
        if (!ctx) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Get pkey context.", cleanup);
        }
        if (EVP_PKEY_verify_init(ctx) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Verify init.", cleanup);
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, rsaPadding[i]) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP_PKEY_CTX_set_rsa_padding", cleanup);
        }
        if (EVP_PKEY_CTX_set_signature_md(ctx, mdType) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Verify set signature md.", cleanup);
        }
        if (1 != EVP_PKEY_verify(ctx, signature, signatureSize, digest, digestSize)) {
            /* padding scheme was not appropriate, next should be tried */
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
        } else {
            /* Verification with selected padding scheme was successful */
            r = TSS2_RC_SUCCESS;
            goto cleanup;
        }
    }
    /* Verification was not successful with one of the possible padding schemes */
    r = TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED;

cleanup:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return r;
}

/**
 * Verifies an RSA signature given as a binary byte buffer.
 *
 * @param[in] publicKey The public key with which the signature is to be
 *            verified
 * @param[in] signature A byte buffer holding the signature to verify
 * @param[in] signatureSize The size of signature in bytes
 * @param[in] digest The digest of the signature to verify
 * @param[in] digestSize The size of digest in bytes. Required to determine the
 *            hash algorithm
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if publicKey, signature or digest is NULL
 * @retval TSS2_FAPI_RC_BAD_VALUE if no hash algorithm that matches digestSize
 *         could be found
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED if the signature could not
 *         be verified
 */
static TSS2_RC
rsa_verify_signature(EVP_PKEY      *publicKey,
                     const uint8_t *signature,
                     size_t         signatureSize,
                     const uint8_t *digest,
                     size_t         digestSize) {
    /* Check for NULL parameters */
    return_if_null(publicKey, "publicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC       r;
    const EVP_MD *mdType;

    /* The hash algorithm of the signature is determined by the digest length */
    switch (digestSize) {
    case TPM2_SHA1_DIGEST_SIZE:
        mdType = EVP_sha1();
        break;
    case TPM2_SHA256_DIGEST_SIZE:
        mdType = EVP_sha256();
        break;
    case TPM2_SHA384_DIGEST_SIZE:
        mdType = EVP_sha384();
        break;
    case TPM2_SHA512_DIGEST_SIZE:
        mdType = EVP_sha512();
        break;
    default:
        return_error(TSS2_FAPI_RC_BAD_VALUE, "Invalid digest size");
    }

    r = rsa_evp_verify_signature(publicKey, signature, signatureSize, mdType, digest, digestSize);
#if HAVE_EVP_SM3 && !defined(OPENSSL_NO_SM3)
    if (r == TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED) {
        /* retry sm3 if digestSize is 32 bytes */
        r = rsa_evp_verify_signature(publicKey, signature, signatureSize, EVP_sm3(), digest,
                                     digestSize);
    }
#endif
    return r;
}

/**
 * Verifies an ECDSA signature given as a binary byte buffer.
 *
 * @param[in] publicKey The public key with which the signature is to be
 *            verified
 * @param[in] signature A byte buffer holding the signature to verify
 * @param[in] signatureSize The size of signature in bytes
 * @param[in] digest The digest of the signature to verify
 * @param[in] digestSize The size of digest in bytes. Required to determine the
 *            hash algorithm
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if publicKey, signature or digest is NULL
 * @retval TSS2_FAPI_RC_BAD_VALUE if no hash algorithm that matches digestSize
 *         could be found
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED if the signature could not
 *         be verified
 */
static TSS2_RC
ecdsa_verify_signature(EVP_PKEY      *publicKey,
                       const uint8_t *signature,
                       size_t         signatureSize,
                       const uint8_t *digest,
                       size_t         digestSize) {
    /* Check for NULL parameters */
    return_if_null(publicKey, "publicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC       r = TSS2_RC_SUCCESS;
    EVP_PKEY_CTX *ctx = NULL;

    if ((ctx = EVP_PKEY_CTX_new(publicKey, NULL)) == NULL || !EVP_PKEY_verify_init(ctx)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Cannot initialize signature verification.",
                   error_cleanup);
    }

    /* Try to verify the signature using ECDSA, note that param 0 is unused */
    int rc = EVP_PKEY_verify(ctx, signature, signatureSize, digest, digestSize);
    if (rc == 0) {
        goto_error(r, TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED,
                   "ECDSA signature verification failed.", error_cleanup);
    } else if (rc < 0) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "ECDSA signature verification failed.",
                   error_cleanup);
    }

error_cleanup:
    OSSL_FREE(ctx, EVP_PKEY_CTX);
    return r;
}

/**
 * Verifies the signature created by a Quote command.
 *
 * @param[in] keyObject A FAPI key with which the signature is verified
 * @param[in] signature A byte buffer holding the signature
 * @param[in] signatureSize The size of signature in bytes
 * @param[in] digest The digest of the signature
 * @param[in] digestSize The size of digest in bytes
 * @param[in] signatureScheme The signature scheme
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if keyObject, signature, digest
 *         or signatureScheme is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_BAD_VALUE if the PEM encoded key could not be decoded
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED if the verification of the
 *         signature fails
 */
TSS2_RC
ifapi_verify_signature_quote(const IFAPI_OBJECT    *keyObject,
                             const uint8_t         *signature,
                             size_t                 signatureSize,
                             const uint8_t         *digest,
                             size_t                 digestSize,
                             const TPMT_SIG_SCHEME *signatureScheme) {
    /* Check for NULL parameters */
    return_if_null(keyObject, "keyObject is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signatureScheme, "signatureScheme is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC       r = TSS2_RC_SUCCESS;
    char         *public_pem_key = NULL;
    int           pem_size;
    EVP_PKEY     *publicKey = NULL;
    BIO          *bufio = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX   *mdctx = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_LIB_CTX *libctx = NULL;
#endif

    /* Check whether or not the key is valid */
    if (keyObject->objectType == IFAPI_KEY_OBJ) {
        /* Compute public key */
        r = ifapi_pub_pem_key_from_tpm(&keyObject->misc.key.public, &public_pem_key, &pem_size);
        goto_if_error(r, "Compute public PEM key.", error_cleanup);
    } else if (keyObject->objectType == IFAPI_EXT_PUB_KEY_OBJ) {
        public_pem_key = strdup(keyObject->misc.ext_pub_key.pem_ext_public);
        check_oom(public_pem_key);
    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong object type", error_cleanup);
    }

    /* Create an OpenSSL object for the key */
    bufio = BIO_new_mem_buf((void *)public_pem_key, (int)strlen(public_pem_key));
    goto_if_null(bufio, "BIO buffer could not be allocated.", TSS2_FAPI_RC_MEMORY, error_cleanup);

    publicKey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    goto_if_null(publicKey, "PEM format could not be decoded.", TSS2_FAPI_RC_BAD_VALUE,
                 error_cleanup);

    /* Create the hash engine */
    if (!(mdctx = EVP_MD_CTX_create())) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP_MD_CTX_create", error_cleanup);
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const EVP_MD *hashAlgorithm = ifapi_get_ossl_hash_md(signatureScheme->details.any.hashAlg);
    if (!hashAlgorithm) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid hash alg.", error_cleanup);
    }

    /* Verify the digest of the signature */
    if (1 != EVP_DigestVerifyInit(mdctx, &pctx, hashAlgorithm, NULL, publicKey)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP_DigestVerifyInit", error_cleanup);
    }
#else
    const char *hashAlgorithm = ifapi_get_hash_md(signatureScheme->details.any.hashAlg);
    if (!hashAlgorithm) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid hash alg.", error_cleanup);
    }

    /* The TPM2 provider may be loaded in the global library context.
     * As we don't want the TPM to be called for these operations, we have
     * to initialize own library context with the default provider. */
    libctx = OSSL_LIB_CTX_new();
    goto_if_null(libctx, "Out of memory", TSS2_FAPI_RC_MEMORY, error_cleanup);

    /* Verify the digest of the signature */
    if (1 != EVP_DigestVerifyInit_ex(mdctx, &pctx, hashAlgorithm, libctx, NULL, publicKey, NULL)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP_DigestVerifyInit_ex", error_cleanup);
    }
#endif
    goto_if_null(pctx, "Out of memory", TSS2_FAPI_RC_MEMORY, error_cleanup);
    if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_RSA) {
        int padding = get_sig_scheme(signatureScheme->scheme);
        if (!padding) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid padding scheme.", error_cleanup);
        }
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, padding)) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP_PKEY_CTX_set_rsa_padding",
                       error_cleanup);
        }
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, digest, digestSize)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP_DigestVerifyUpdate", error_cleanup);
    }
    if (1 != EVP_DigestVerifyFinal(mdctx, signature, signatureSize)) {
        goto_error(r, TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED, "EVP_DigestSignFinal",
                   error_cleanup);
    }

error_cleanup:
    EVP_MD_CTX_destroy(mdctx);
    SAFE_FREE(public_pem_key);
    EVP_PKEY_free(publicKey);
    BIO_free(bufio);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_LIB_CTX_free(libctx);
#endif
    return r;
}

/**
 * Verifies a signature using a given FAPI public key.
 *
 * @param[in] keyObject The FAPI public key used for verification
 * @param[in] signature The signature to verify
 * @param[in] signatureSize The size of signature in bytes
 * @param[in] digest The digest of the signature
 * @param[in] digestSize The size of digest in bytes
 *
 * @retval TSS2_RC_SUCCESS In case of success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if keyObject, signature or digest is NULL
 * @retval TSS2_FAPI_RC_BAD_VALUE if the type of the key is wrong
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED if the verification of the
 *         signature fails
 *
 */
TSS2_RC
ifapi_verify_signature(const IFAPI_OBJECT *keyObject,
                       const uint8_t      *signature,
                       size_t              signatureSize,
                       const uint8_t      *digest,
                       size_t              digestSize) {
    /* Check for NULL parameters */
    return_if_null(keyObject, "keyObject is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC   r = TSS2_RC_SUCCESS;
    char     *public_pem_key = NULL;
    int       pem_size;
    EVP_PKEY *publicKey = NULL;
    BIO      *bufio = NULL;

    /* Check whether or not the key is valid */
    if (keyObject->objectType == IFAPI_KEY_OBJ) {
        /* Compute public key */
        r = ifapi_pub_pem_key_from_tpm(&keyObject->misc.key.public, &public_pem_key, &pem_size);
        goto_if_error(r, "Compute public PEM key.", error_cleanup);
    } else if (keyObject->objectType == IFAPI_EXT_PUB_KEY_OBJ) {
        public_pem_key = strdup(keyObject->misc.ext_pub_key.pem_ext_public);
        check_oom(public_pem_key);
    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong object type", error_cleanup);
    }

    /* Convert the key to an OpenSSL object */
    bufio = BIO_new_mem_buf((void *)public_pem_key, (int)strlen(public_pem_key));
    goto_if_null(bufio, "Out of memory.", TSS2_FAPI_RC_MEMORY, error_cleanup);
    publicKey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    goto_if_null(publicKey, "PEM format could not be decoded.", TSS2_FAPI_RC_MEMORY, error_cleanup);

    /* Call a suitable local function for the verification */
    if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_RSA) {
        r = rsa_verify_signature(publicKey, signature, signatureSize, digest, digestSize);
        goto_if_error(r, "Verify RSA signature.", error_cleanup);

    } else if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_EC) {
        r = ecdsa_verify_signature(publicKey, signature, signatureSize, digest, digestSize);
        goto_if_error(r, "Verify ECC signature", error_cleanup);

    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong key type", error_cleanup);
    }

error_cleanup:
    SAFE_FREE(public_pem_key);
    EVP_PKEY_free(publicKey);
    if (bufio)
        BIO_free(bufio);
    return r;
}

/** Openssl rsa encryption with OAEP padding.
 *
 * @param[in] pem_key The public RSA key.
 * @param[in] rsa_decrypt_scheme The padding scheme.
 * @param[in] plainText The data to be encrypted.
 *  @param[in] plainTextSize The size of the data to be encrypted.
 * @param[out] cipherText The encrypted data.
 * @param[out] cipherTextSize The size of the encrypted data.
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 */
TSS2_RC
ifapi_rsa_encrypt(const char             *pem_key,
                  const TPMT_RSA_DECRYPT *rsa_decrypt_scheme,
                  const uint8_t          *plainText,
                  size_t                  plainTextSize,
                  uint8_t               **cipherText,
                  size_t                 *cipherTextSize) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY     *publicKey = NULL;
    BIO          *bufio = NULL;
    TSS2_RC       r;
    const EVP_MD *evp_md;

    /* Convert the pem key to an OpenSSL object */
    bufio = BIO_new_mem_buf((void *)pem_key, (int)strlen(pem_key));
    goto_if_null(bufio, "Out of memory.", TSS2_FAPI_RC_MEMORY, cleanup);

    publicKey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    goto_if_null(publicKey, "PEM format could not be decoded.", TSS2_FAPI_RC_MEMORY, cleanup);

    if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_RSA) {
        if (rsa_decrypt_scheme->scheme == TPM2_ALG_OAEP) {
            switch (rsa_decrypt_scheme->details.oaep.hashAlg) {
            case TPM2_ALG_SHA1:
                evp_md = EVP_sha1();
                break;
            case TPM2_ALG_SHA256:
                evp_md = EVP_sha256();
                break;
            case TPM2_ALG_SHA384:
                evp_md = EVP_sha384();
                break;
            case TPM2_ALG_SHA512:
                evp_md = EVP_sha512();
                break;
#if HAVE_EVP_SM3 && !defined(OPENSSL_NO_SM3)
            case TPM2_ALG_SM3_256:
                evp_md = EVP_sm3();
                break;
#endif
            default:
                goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Invalid hash alg.", cleanup);
            }
        } else {
            LOG_WARNING("OEAP (sha256) will be used for encryption padding.");
            evp_md = EVP_sha256();
        }

        ctx = EVP_PKEY_CTX_new(publicKey, NULL);
        goto_if_null(ctx, "EVP_PKEY_CTX_new.", TSS2_FAPI_RC_GENERAL_FAILURE, cleanup);
        if (EVP_PKEY_encrypt_init(ctx) <= 0
            || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, evp_md) <= 0
            || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, evp_md) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP init encrypt.", cleanup);
        }

        /* Determine buffer length */
        if (EVP_PKEY_encrypt(ctx, NULL, cipherTextSize, plainText, plainTextSize) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP encrypt determine size.", cleanup);
        }

        *cipherText = OPENSSL_malloc(*cipherTextSize);
        if (EVP_PKEY_encrypt(ctx, *cipherText, cipherTextSize, plainText, plainTextSize) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP encrypt.", cleanup);
        }
        r = TSS2_RC_SUCCESS;
    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "No RSA public key.", cleanup);
    }

cleanup:
    if (bufio)
        BIO_free(bufio);
    if (publicKey)
        EVP_PKEY_free(publicKey);
    if (ctx)
        OSSL_FREE(ctx, EVP_PKEY_CTX);
    return r;
}
