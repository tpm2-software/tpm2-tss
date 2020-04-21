/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <curl/curl.h>
#include <openssl/err.h>

#include "fapi_certificates.h"
#include "fapi_util.h"
#include "util/aux_util.h"
#include "fapi_crypto.h"
#define LOGMODULE fapi
#include "util/log.h"

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#define EC_POINT_set_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_set_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

#define EC_POINT_get_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_get_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

#else
#define EC_POINT_set_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_set_affine_coordinates_GFp(group, tpm_pub_key, bn_x, bn_y, dmy)

#define EC_POINT_get_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_get_affine_coordinates_GFp(group, tpm_pub_key, bn_x, bn_y, dmy)
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */

/** Context to hold temporary values for ifapi_crypto */
typedef struct _IFAPI_CRYPTO_CONTEXT {
    /** The hash engine's context */
    EVP_MD_CTX *osslContext;
    /** The currently used hash algorithm */
    const EVP_MD *osslHashAlgorithm;
    /** The size of the hash's digest */
    size_t hashSize;
} IFAPI_CRYPTO_CONTEXT;

/** A singleton crypto engine for hash operations */
static ENGINE *engine = NULL;

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
ifapi_get_profile_sig_scheme(
    const IFAPI_PROFILE *profile,
    const TPMT_PUBLIC *tpmPublic,
    TPMT_SIG_SCHEME *signatureScheme)
{
    /* Check for NULL parameters */
    return_if_null(profile, "profile is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(tpmPublic, "tpmPublic is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signatureScheme, "signatureScheme is NULL",
            TSS2_FAPI_RC_BAD_REFERENCE);

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

static const TPM2B_PUBLIC templateRsaSign = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA1,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN
                             ),
        .authPolicy = {
            .size = 0,
            .buffer = 0,
        },
        .parameters.rsaDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_NULL,
                .keyBits.aes = 128,
                .mode.aes = TPM2_ALG_CFB,
            },
            .scheme = {
                .scheme = TPM2_ALG_RSAPSS,
                .details.rsapss.hashAlg = TPM2_ALG_SHA1,
            },
            .keyBits = 2048,
            .exponent = 65537,
        },
        .unique.rsa = {
            .size = 0,
            .buffer = {},
        }
    }
};

/**
 * A FAPI template for ECC signing keys
 */
static const TPM2B_PUBLIC templateEccSign = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA1,
        .objectAttributes = (
                             TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN
                             ),
        .authPolicy = {
            .size = 0,
        },

        .parameters.eccDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_NULL,
                .keyBits.aes = 128,
                .mode.aes = TPM2_ALG_ECB,
            },
            .scheme = {
                .scheme = TPM2_ALG_ECDSA,
                .details = { .ecdsa = { .hashAlg = TPM2_ALG_SHA256 }},
            },
            .curveID = TPM2_ECC_BN_P256,
            .kdf = { .scheme = TPM2_ALG_NULL, .details = {} }
        },
        .unique.ecc = {
            .x = { .size = 0, .buffer = {} },
            .y = { .size = 0, .buffer = {} },
        },
    },
};

/**
 * Initializes a FAPI key template for a given signature algorithm.
 *
 * @param[in]  signatureAlgorithm The signature algorithm to use. Must be
 *             TPM2_ALG_RSA or TPM2_ALG_ECC
 * @param[out] public The template to initialize
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if template is NULL
 * @retval TSS2_FAPI_RC_BAD_VALUE if signatureAlgorithm is not TPM2_ALG_RSA or
 *         TPM2_ALG_ECC
 */
TSS2_RC
ifapi_initialize_sign_public(TPM2_ALG_ID signatureAlgorithm,
        TPM2B_PUBLIC *public) {

    /* Check for NULL parameters */
    return_if_null(public, "public is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Initialize the template */
    if (signatureAlgorithm == TPM2_ALG_RSA) {
        /* RSA key template */
        memcpy(public, &templateRsaSign, sizeof(TPM2B_PUBLIC));
    } else if (signatureAlgorithm == TPM2_ALG_ECC) {
        /* ECC key template */
        memcpy(public, &templateEccSign, sizeof(TPM2B_PUBLIC));
    } else {
        /* Invalid key type */
        LOG_ERROR("No suitable template found");
        return TSS2_FAPI_RC_BAD_VALUE;
    }
    return TSS2_RC_SUCCESS;
}

/**
 * Converts an openSSL BIGNUM into a binary byte buffer using.
 *
 * @param[in]  bn The BIGNUM to convert
 * @param[out] bin The binary buffer to which the bignum is converted
 * @param[in]  binSize The size of bin in bytes
 *
 * @retval 1 if the conversion was successful
 * @retval 0 if one of the parameters is NULL
 */
static int
ifapi_bn2binpad(const BIGNUM *bn, unsigned char *bin, int binSize)
{
    /* Check for NULL parameters */
    return_if_null(bn, "bn is NULL", 0);
    return_if_null(bin, "bin is NULL", 0);

    /* Convert bn */
    int bnSize = BN_num_bytes(bn);
    int offset = binSize - bnSize;
    memset(bin, 0, offset);
    BN_bn2bin(bn, bin + offset);
    return 1;
}

/**
 * Returns the singleton hash engine for the use in ifapi_hash operations. If
 * it does not yet exist, this function creates it.
 *
 * @retval A singleton hash engine
 */
static ENGINE *
get_engine()
{
    /* If an engine is present, it is returned */
    if (engine)
        return engine;
    /* Otherwise, engine is created and returned */
    engine = ENGINE_by_id(NULL);
    return engine;
}

/**
 * Returns a suitable openSSL hash algorithm identifier for a given TSS hash
 * algorithm identifier.
 *
 * @param[in] hashAlgorithm The TSS hash algorithm identifier
 *
 * @retval An openSSL hash algorithm identifier if one that is suitable to
 *         hashAlgorithm could be found
 * @retval NULL if no suitable hash algorithm identifier could be found
 */
static const EVP_MD *
get_hash_md(TPM2_ALG_ID hashAlgorithm)
{
    switch (hashAlgorithm) {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
    case TPM2_ALG_SHA256:
        return EVP_sha256();
    case TPM2_ALG_SHA384:
        return EVP_sha384();
    case TPM2_ALG_SHA512:
        return EVP_sha512();
    default:
        return NULL;
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
get_sig_scheme(TPM2_ALG_ID signatureScheme)
{
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
ifapi_tpm_ecc_sig_to_der(
    const TPMT_SIGNATURE *tpmSignature,
    uint8_t **signature,
    size_t *signatureSize)
{
    /* Check for NULL parameters */
    return_if_null(tpmSignature, "tpmSignature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    ECDSA_SIG *ecdsaSignature = NULL;
    BIGNUM *bns = NULL, *bnr = NULL;
    int osslRC;
    TSS2_RC r;
    uint8_t *signatureWalking;

    /* Initialize an OpenSSL ECDSA signature which servers as an intermediate
     * between the TSS ECDSA signature and the DER byte buffer */
    ecdsaSignature = ECDSA_SIG_new();
    goto_if_null(ecdsaSignature, "Out of memory", TSS2_FAPI_RC_MEMORY,
                 cleanup);

    bns = BN_bin2bn(&tpmSignature->signature.ecdsa.signatureS.buffer[0],
                    tpmSignature->signature.ecdsa.signatureS.size, NULL);
    goto_if_null(bns, "Out of memory", TSS2_FAPI_RC_MEMORY, cleanup);

    bnr = BN_bin2bn(&tpmSignature->signature.ecdsa.signatureR.buffer[0],
                    tpmSignature->signature.ecdsa.signatureR.size, NULL);
    goto_if_null(bnr, "Out of memory", TSS2_FAPI_RC_MEMORY, cleanup);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    ecdsaSignature->s = bns;
    ecdsaSignature->r = bnr;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    ECDSA_SIG_set0(ecdsaSignature, bnr, bns);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    osslRC = i2d_ECDSA_SIG(ecdsaSignature, NULL);
    if (osslRC == -1) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "OSSL error", cleanup);
    }

    /* Initialize the byte buffer for the DER representation */
    *signature = malloc(osslRC);
    signatureWalking = *signature;
    goto_if_null(*signature, "Out of memory", TSS2_FAPI_RC_MEMORY, cleanup);

    if (signatureSize != NULL) {
        *signatureSize = osslRC;
    }

    /* Convert the OpenSSL ECDSA signature to the DER buffer */
    osslRC = i2d_ECDSA_SIG(ecdsaSignature, &signatureWalking);
    if (!osslRC) {
        free(*signature);
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
 * Converts a public RSA key created by the TPM into one that can be used by
 * OpenSSL.
 *
 * @param[in]  tpmPublicKey The public RSA key created by the TPM
 * @param[out] evpPublicKey The converted public RSA key that can be used by
 *             OpenSSL
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if one of the parameters is NULL
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
static TSS2_RC
ossl_rsa_pub_from_tpm(const TPM2B_PUBLIC *tpmPublicKey, EVP_PKEY *evpPublicKey)
{
    /* Check for NULL parameters */
    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(evpPublicKey, "evpPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Initialize the RSA parameters */
    TSS2_RC r;
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *dmp1 = BN_new();
    BIGNUM *dmq1 = BN_new();
    BIGNUM *iqmp = BN_new();
    BIGNUM *n = BN_bin2bn(tpmPublicKey->publicArea.unique.rsa.buffer,
                          tpmPublicKey->publicArea.unique.rsa.size, NULL);

    if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp || !rsa) {
        goto_error(r, TSS2_FAPI_RC_MEMORY, "Out of memory", error_cleanup);
    }

    BN_set_word(d, 0);
    BN_set_word(p, 0);
    BN_set_word(q, 0);
    BN_set_word(dmp1, 0);
    BN_set_word(dmq1, 0);
    BN_set_word(iqmp, 0);
    uint32_t exp;
    if (tpmPublicKey->publicArea.parameters.rsaDetail.exponent == 0)
        exp = 65537;
    else
        exp = tpmPublicKey->publicArea.parameters.rsaDetail.exponent;
    if (1 != BN_set_word(e, exp)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Could not set exponent.", error_cleanup);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000
    rsa->e = e;
    rsa->n = n;
    rsa->d = d;
    rsa->p = p;
    rsa->q = q;
    rsa->dmp1 = dmp1;
    rsa->dmq1 = dmq1;
    rsa->iqmp = iqmp;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    /* Assign the parameters to the key */
    if (!EVP_PKEY_assign_RSA(evpPublicKey, rsa)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Assign rsa key",
                   error_cleanup);
    }
    return TSS2_RC_SUCCESS;

error_cleanup:
    OSSL_FREE(rsa, RSA);
    OSSL_FREE(e, BN);
    OSSL_FREE(n, BN);
    OSSL_FREE(d, BN);
    OSSL_FREE(p, BN);
    OSSL_FREE(q, BN);
    OSSL_FREE(dmp1, BN);
    OSSL_FREE(dmq1, BN);
    OSSL_FREE(iqmp, BN);
    return r;
}

/**
 * Converts a public ECC key created by the TPM into one that can be used by
 * OpenSSL.
 *
 * @param[in]  tpmPublicKey The public ECC key created by the TPM
 * @param[out] evpPublicKey The converted public ECC key that can be used by
 *             OpenSSL
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if one of the parameters is NULL
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
static TSS2_RC
ossl_ecc_pub_from_tpm(const TPM2B_PUBLIC *tpmPublicKey, EVP_PKEY *evpPublicKey)
{
    /* Check for NULL parameters */
    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(evpPublicKey, "evpPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r;
    EC_GROUP *ecgroup = NULL;
    int curveId;
    BIGNUM *x = NULL, *y = NULL;
    EC_KEY *ecKey = EC_KEY_new();
    return_if_null(ecKey, "Out of memory.", TSS2_FAPI_RC_MEMORY);

    /* Find the curve of the ECC key */
    switch (tpmPublicKey->publicArea.parameters.eccDetail.curveID) {
    case TPM2_ECC_NIST_P192:
        curveId = NID_X9_62_prime192v1;
        break;
    case TPM2_ECC_NIST_P224:
        curveId = NID_secp224r1;
        break;
    case TPM2_ECC_NIST_P256:
        curveId = NID_X9_62_prime256v1;
        break;
    case TPM2_ECC_NIST_P384:
        curveId = NID_secp384r1;
        break;
    case TPM2_ECC_NIST_P521:
        curveId = NID_secp521r1;
        break;
    default:
        return_error(TSS2_FAPI_RC_BAD_VALUE,
                     "ECC curve not implemented.");
    }

    /* Initialize the OpenSSL ECC key with its group */
    ecgroup = EC_GROUP_new_by_curve_name(curveId);
    goto_if_null(ecgroup, "new EC group.", TSS2_FAPI_RC_GENERAL_FAILURE,
                  error_cleanup);

    if (!EC_KEY_set_group(ecKey, ecgroup)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EC_KEY_set_group",
                   error_cleanup);
    }
    EC_GROUP_free(ecgroup);

    /* Set the ECC parameters in the OpenSSL key */
    x = BN_bin2bn(tpmPublicKey->publicArea.unique.ecc.x.buffer,
                  tpmPublicKey->publicArea.unique.ecc.x.size, NULL);

    y = BN_bin2bn(tpmPublicKey->publicArea.unique.ecc.y.buffer,
                  tpmPublicKey->publicArea.unique.ecc.y.size, NULL);

    if (!x || !y) {
        goto_error(r, TSS2_FAPI_RC_MEMORY, "Out of memory", error_cleanup);
    }

    if (!EC_KEY_set_public_key_affine_coordinates(ecKey, x, y)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "EC_KEY_set_public_key_affine_coordinates", error_cleanup);
    }

    if (!EVP_PKEY_assign_EC_KEY(evpPublicKey, ecKey)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Assign ecc key",
                   error_cleanup);
    }
    /* Needed for older OSSL versions. */
    EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);
    OSSL_FREE(y, BN);
    OSSL_FREE(x, BN);
    return TSS2_RC_SUCCESS;

error_cleanup:
    OSSL_FREE(y, BN);
    OSSL_FREE(x, BN);
    OSSL_FREE(ecKey, EC_KEY);
    return r;
}

/**
 * Convert a TPM public key into a PEM formatted byte buffer. This can be
 * used by TLS libraries.
 *
 * @param[in]  tpmPublicKey The public key created by the TPM
 * @param[out] pemKey A byte buffer that will hold the PEM representation of
 *             the public key  (callee allocated)
 * @param[out] pemKeySize The size of pemKey in bytes
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_BAD_REFERENCE if tpmPublicKey or pemKeySize are NULL
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
TSS2_RC
ifapi_pub_pem_key_from_tpm(
    const TPM2B_PUBLIC *tpmPublicKey,
    char **pemKey,
    int *pemKeySize)
{
    /* Check for NULL parameters */
    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(pemKeySize, "pemKeySize is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    EVP_PKEY *evpPublicKey = NULL;
    BIO *bio = NULL;
    TSS2_RC r = TPM2_RC_SUCCESS;

    evpPublicKey = EVP_PKEY_new();
    goto_if_null2(evpPublicKey, "Out of memory.", r, TSS2_FAPI_RC_MEMORY, cleanup);

    /* Memory IO will be used for OSSL key conversion */
    bio = BIO_new(BIO_s_mem());
    goto_if_null2(evpPublicKey, "Out of memory.", r, TSS2_FAPI_RC_MEMORY, cleanup);

    if (tpmPublicKey->publicArea.type == TPM2_ALG_RSA) {
        r = ossl_rsa_pub_from_tpm(tpmPublicKey, evpPublicKey);
    } else if (tpmPublicKey->publicArea.type == TPM2_ALG_ECC)
        r = ossl_ecc_pub_from_tpm(tpmPublicKey, evpPublicKey);
    else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Invalid alg id.", cleanup);
    }
    goto_if_error(r, "Get ossl public key.", cleanup);

    if (!PEM_write_bio_PUBKEY(bio, evpPublicKey)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "PEM_write_bio_PUBKEY",
                   cleanup);
    }

    /* Determine the size of the data written */
    *pemKeySize = BIO_get_mem_data(bio, pemKey);
    *pemKey = malloc(*pemKeySize+1);
    goto_if_null(*pemKey, "Out of memory.", TSS2_FAPI_RC_MEMORY,
            cleanup);
    memset(*pemKey, 0, *pemKeySize + 1);

    /* Get the byte buffer written to the BIO object */
    int readSize = BIO_read(bio, *pemKey, *pemKeySize);
    if (readSize != *pemKeySize) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid BIO_read",
                   cleanup);
    }

cleanup:
    EVP_PKEY_free(evpPublicKey);
    BIO_free(bio);
    return r;
}

/** Converts an ECDSA signature from a DER encoded byte buffer into the
 * TPM format. It can then be verified by the TPM.
 *
 * @param[in]  signature A DER encoded byte buffer holding the signature
 * @param[in]  signatureSize The size of signature in bytes
 * @param[in]  keySize The size of the verification key
 * @param[in]  hashAlgorithm The TSS identifier of the hash algorithm to use
 * @param[out] tpmSignature The signature in the TPM format
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if signature or tpmSignature is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 */
static TSS2_RC
ifapi_ecc_der_sig_to_tpm(
    const unsigned char *signature,
    size_t signatureSize,
    int keySize,
    TPMI_ALG_HASH hashAlgorithm,
    TPMT_SIGNATURE *tpmSignature)
{
    /* Check for NULL parameters */
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(tpmSignature, "tpmSignature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Initialize the ECDSA signature components */
    ECDSA_SIG *ecdsaSignature = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000
    BIGNUM *bnr;
    BIGNUM *bns;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    const BIGNUM *bnr;
    const BIGNUM *bns;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    d2i_ECDSA_SIG(&ecdsaSignature, &signature, signatureSize);
    return_if_null(ecdsaSignature, "Invalid DER signature",
                   TSS2_FAPI_RC_GENERAL_FAILURE);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    bns = ecdsaSignature->s;
    bnr = ecdsaSignature->r;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    ECDSA_SIG_get0(ecdsaSignature, &bnr, &bns);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    /* Writing them to the TPM format signature */
    tpmSignature->signature.ecdsa.hash = hashAlgorithm;
    tpmSignature->sigAlg = TPM2_ALG_ECDSA; /**< only ECDSA is used by FAPI */
    ifapi_bn2binpad(bnr, &tpmSignature->signature.ecdsa.signatureR.buffer[0],
                       keySize);
    tpmSignature->signature.ecdsa.signatureR.size = keySize;
    ifapi_bn2binpad(bns, &tpmSignature->signature.ecdsa.signatureS.buffer[0],
                       keySize);
    tpmSignature->signature.ecdsa.signatureS.size = keySize;
    OSSL_FREE(ecdsaSignature, ECDSA_SIG);
    //OSSL_FREE(bnr, BN);
    //OSSL_FREE(bns, BN);
    return TSS2_RC_SUCCESS;
}

/** Convert signature from DER to TPM format.
 *
 * The signature in DER format is converted to TPM format to
 * enable verification by the TPM.
 *
 * @param[in] tpmPublic The public information of the signature key
 * @param[in] signature A byte buffer holding the DER encoded signature
 * @param[in] signatureSize The size of signature in bytes
 * @param[in] hashAlgorithm The TSS identifier for the hash algorithm used
 *            to compute the digest
 * @param[out] tpmSignature The signature in TPM format
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if tpmPublic, signature or tpmSignature is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
TSS2_RC
ifapi_der_sig_to_tpm(
    const TPMT_PUBLIC *tpmPublic,
    const unsigned char *signature,
    size_t signatureSize,
    TPMI_ALG_HASH hashAlgorithm,
    TPMT_SIGNATURE *tpmSignature)
{
    /* Check for NULL parameters */
    return_if_null(tpmPublic, "tpmPublic is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(tpmSignature, "tpmSignature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Convert the signature */
    if (tpmPublic->type == TPM2_ALG_RSA) {
        if (tpmPublic->parameters.rsaDetail.scheme.scheme == TPM2_ALG_RSAPSS) {
            tpmSignature->sigAlg = TPM2_ALG_RSAPSS;
            tpmSignature->signature.rsapss.hash = hashAlgorithm;
            tpmSignature->signature.rsapss.sig.size = signatureSize;
            memcpy(&tpmSignature->signature.rsapss.sig.buffer[0], signature,
                    signatureSize);
        } else if (tpmPublic->parameters.rsaDetail.scheme.scheme == TPM2_ALG_RSASSA) {
            tpmSignature->sigAlg = TPM2_ALG_RSASSA;
            tpmSignature->signature.rsassa.hash = hashAlgorithm;
            tpmSignature->signature.rsassa.sig.size = signatureSize;
            memcpy(&tpmSignature->signature.rsassa.sig.buffer[0], signature,
                    signatureSize);
        } else {
            return_error(TSS2_FAPI_RC_BAD_VALUE, "Invalid RSA scheme.");

        }
    } else if (tpmPublic->type == TPM2_ALG_ECC) {
        return ifapi_ecc_der_sig_to_tpm(signature, signatureSize,
                                        tpmPublic->unique.ecc.x.size, hashAlgorithm,
                                        tpmSignature);
    } else {
        return_error(TSS2_FAPI_RC_BAD_VALUE, "Invalid key tpye.");
    }
    return TSS2_RC_SUCCESS;
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
rsa_verify_signature(
    EVP_PKEY *publicKey,
    const uint8_t *signature,
    size_t signatureSize,
    const uint8_t *digest,
    size_t digestSize)
{
    /* Check for NULL parameters */
    return_if_null(publicKey, "publicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r;
    const EVP_MD *mdType;
    EVP_PKEY_CTX *ctx = NULL;

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
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Invalid digest size", cleanup);
    }

    /* Try all possible padding schemes for verification */
    for (int i = 0; i < N_PADDING; i++) {
        ctx = EVP_PKEY_CTX_new(publicKey, NULL);
        if (!ctx) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Get pkey context.",
                       cleanup);
        }
        if (EVP_PKEY_verify_init(ctx) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Verify init.",
                       cleanup);
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, rsaPadding[i]) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "EVP_PKEY_CTX_set_rsa_padding", cleanup);
        }
        if (EVP_PKEY_CTX_set_signature_md(ctx, mdType) <= 0) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Verify set signature md.", cleanup);
        }
        if (1 != EVP_PKEY_verify(ctx, signature, signatureSize, digest, digestSize)) {
            /* padding scheme was not appropriate, next should be tried */
            EVP_PKEY_CTX_free(ctx);
        } else {
            /* Verification with selected padding scheme was successful */
            r = TSS2_RC_SUCCESS;
            goto cleanup;
        }
    }
    /* Verification was not successful with one of the possible padding schemes */
    r = TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED;

cleanup:
    EVP_PKEY_CTX_free(ctx);
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
ecdsa_verify_signature(
    EVP_PKEY *publicKey,
    const uint8_t *signature,
    size_t signatureSize,
    const uint8_t *digest,
    size_t digestSize)
{
    /* Check for NULL parameters */
    return_if_null(publicKey, "publicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r = TSS2_RC_SUCCESS;
    EC_KEY *eccKey = NULL;

    eccKey = EVP_PKEY_get1_EC_KEY(publicKey);

    /* Try to verify the signature using ECDSA, note that param 0 is unused */
    int rc = ECDSA_verify(0, digest, digestSize, signature, signatureSize, eccKey);
    if (rc == 0) {
        goto_error(r, TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED,
                   "ECDSA signature verification failed.", error_cleanup);
    } else if (rc < 0) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "ECDSA signature verification failed.", error_cleanup);
    }

error_cleanup:
    OSSL_FREE(eccKey, EC_KEY);
    return r;
}

/**
 * Gets an object with the TPM-relevant public information of an OpenSSL
 * RSA public key.
 *
 * @param[in,out] profile The crypto profile from which parameters are retrieved
 * @param[in]  publicKey The public key for which the public information is
 *             retrieved
 * @param[out] tpmPublic The public information of publicKey
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if profile, publicKey or tpmPublic is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 */
static TSS2_RC
get_rsa_tpm2b_public_from_evp(
    EVP_PKEY *publicKey,
    TPM2B_PUBLIC *tpmPublic)
{
    /* Check for NULL parameters */
    return_if_null(publicKey, "publicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(tpmPublic, "tpmPublic is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Extract the public information */
    TSS2_RC r = TSS2_RC_SUCCESS;
    RSA *rsaKey = EVP_PKEY_get1_RSA(publicKey);
    return_if_null(rsaKey, "Out of memory.", TSS2_FAPI_RC_MEMORY);
    const BIGNUM *e = NULL, *n = NULL;
    int rsaKeySize = RSA_size(rsaKey);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    e = rsaKey->e;
    n = rsaKey->n;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    RSA_get0_key(rsaKey, &n, &e, NULL);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    tpmPublic->publicArea.unique.rsa.size = rsaKeySize;
    if (1 != ifapi_bn2binpad(n, &tpmPublic->publicArea.unique.rsa.buffer[0],
                             rsaKeySize)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Write big num byte buffer", cleanup);
    }
    tpmPublic->publicArea.parameters.rsaDetail.keyBits = rsaKeySize * 8;
    tpmPublic->publicArea.parameters.rsaDetail.exponent = BN_get_word(e);

cleanup:
    OSSL_FREE(rsaKey, RSA);
    return r;
}

/**
 * Gets an object with the TPM-relevant public information of an OpenSSL
 * ECC public key.
 *
 * @param[in,out] profile The crypto profile to retrieve parameters from.
 * @param[in]  publicKey The public key for which the public information is
 *             retrieved
 * @param[out] tpmPublic The public information of publicKey
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if profile, publicKey or tpmPublic is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
static TSS2_RC
get_ecc_tpm2b_public_from_evp(
    EVP_PKEY *publicKey,
    TPM2B_PUBLIC *tpmPublic)
{
    /* Check for NULL parameters */
    return_if_null(publicKey, "publicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(tpmPublic, "tpmPublic is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Initialize variables that will contain the relevant information */
    TSS2_RC r = TSS2_RC_SUCCESS;
    EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(publicKey);
    return_if_null(ecKey, "Out of memory.", TSS2_FAPI_RC_MEMORY);
    const EC_GROUP *ecGroup;
    const EC_POINT *publicPoint;
    int curveId;
    size_t ecKeySize;
    BIGNUM *bnX = NULL;
    BIGNUM *bnY = NULL;
    TPMI_ECC_CURVE tpmCurveId;

    if (!ecKey) {
        return_error(TSS2_FAPI_RC_GENERAL_FAILURE, "No ECC key!");
    }

    /* Retrieve the relevant information and write it to tpmPublic */
    ecGroup = EC_KEY_get0_group(ecKey);
    publicPoint = EC_KEY_get0_public_key(ecKey);
    curveId = EC_GROUP_get_curve_name(ecGroup);
    ecKeySize = EC_GROUP_get_degree(ecGroup) / 8;
    tpmPublic->publicArea.unique.ecc.x.size = ecKeySize;
    tpmPublic->publicArea.unique.ecc.y.size = ecKeySize;

    if (!(bnX = BN_new())) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Create bignum", cleanup);
    }

    if (!(bnY = BN_new())) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Create bignum", cleanup);
    }

    if (1 != EC_POINT_get_affine_coordinates_tss(ecGroup, publicPoint,
                                                 bnX, bnY, NULL)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Get affine coordinates", cleanup);
    }
    if (1 != ifapi_bn2binpad(bnX, &tpmPublic->publicArea.unique.ecc.x.buffer[0],
                             ecKeySize)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Write big num byte buffer", cleanup);
    }
    if (1 != ifapi_bn2binpad(bnY, &tpmPublic->publicArea.unique.ecc.y.buffer[0],
                             ecKeySize)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Write big num byte buffer", cleanup);
    }
    switch (curveId) {
    case NID_X9_62_prime192v1:
        tpmCurveId = TPM2_ECC_NIST_P192;
        break;
    case NID_secp224r1:
        tpmCurveId = TPM2_ECC_NIST_P224;
        break;
    case NID_X9_62_prime256v1:
        tpmCurveId = TPM2_ECC_NIST_P256;
        break;
    case NID_secp384r1:
        tpmCurveId = TPM2_ECC_NIST_P384;
        break;
    case NID_secp521r1:
        tpmCurveId = TPM2_ECC_NIST_P521;
        break;
    default:
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE,
                   "Curve %x not implemented", cleanup, curveId);
    }
    tpmPublic->publicArea.parameters.eccDetail.curveID = tpmCurveId;

cleanup:
    OSSL_FREE(ecKey, EC_KEY);
    OSSL_FREE(bnX, BN);
    OSSL_FREE(bnY, BN);
    return r;
}

/**
 * Converts a given PEM key into an EVP public key object.
 *
 * @param[in] pemKey A byte buffer holding the PEM key to convert
 * @param[out] publicKey An EVP public key
 *
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if any of the parameters is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_BAD_VALUE if the PEM key could not be decoded
 */
static TSS2_RC
ifapi_get_evp_from_pem(const char *pemKey, EVP_PKEY **publicKey) {
    /* Check for NULL parameters */
    return_if_null(pemKey, "pemKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(publicKey, "publicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r = TSS2_RC_SUCCESS;
    BIO *bufio = NULL;

    /* Use BIO for conversion */
    bufio = BIO_new_mem_buf((void *)pemKey, strlen(pemKey));
    goto_if_null(bufio, "BIO buffer could not be allocated.",
                 TSS2_FAPI_RC_MEMORY, cleanup);

    /* Convert the key */
    *publicKey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    goto_if_null(*publicKey, "PEM format could not be decoded.",
                 TSS2_FAPI_RC_BAD_VALUE, cleanup);
cleanup:
    BIO_free(bufio);
    return r;
}

/**
 * Returns the TPM algorithm identifier that matches to the signature algorithm
 * of a given PEM key.
 *
 * @param[in] pemKey The public key from which the signature algorithm is retrieved
 *
 * @retval TPM2_ALG_RSA if pemKey holds an RSA key
 * @retval TPM2_ALG_ECC if pemKey holds an ECC key
 * @retval TPM2_ALG_ERROR if the signature algorithm could not be determined
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
TPM2_ALG_ID
ifapi_get_signature_algorithm_from_pem(const char *pemKey) {
    /* Check for NULL parameters */
    return_if_null(pemKey, "pemKey is NULL", TPM2_ALG_ERROR);

    /* Get an EVP object for the key */
    EVP_PKEY * publicKey = NULL;
    TPM2_ALG_ID algorithmId = TPM2_ALG_ERROR;
    TSS2_RC r = ifapi_get_evp_from_pem(pemKey, &publicKey);
    if (r != TSS2_RC_SUCCESS || publicKey == NULL) {
        LOG_ERROR("Could not get an EVP key from the PEM key");
        algorithmId = TPM2_ALG_ERROR;
        goto cleanup;
    }

    /* Determine the signature algorithm of the converted key */
    if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_RSA) {
        algorithmId = TPM2_ALG_RSA;
    } else if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_EC) {
        algorithmId = TPM2_ALG_ECC;
    } else {
        algorithmId = TPM2_ALG_ERROR;
    }

cleanup:
    OSSL_FREE(publicKey, EVP_PKEY);
    return algorithmId;
}

/**
 * Gets an object with the TPM-relevant public information of a PEM encoded
 * public key. The information is gathered from the key itself and the currently
 * used FAPI profile.
 *
 * @param[in]  pemKey A byte buffer holding the PEM encoded public key for
 *             which the public information is retrieved
 * @param[out] tpmPublic The public information of pemKey
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if profile, pemKey or tpmPublic is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
TSS2_RC
ifapi_get_tpm2b_public_from_pem(
    const char *pemKey,
    TPM2B_PUBLIC *tpmPublic)
{
    /* Check for NULL parameters */
    return_if_null(pemKey, "pemKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(tpmPublic, "public is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r = TSS2_RC_SUCCESS;
    EVP_PKEY *publicKey = NULL;
    r = ifapi_get_evp_from_pem(pemKey, &publicKey);
    goto_if_error(r, "Get EVP key from PEM", cleanup);

    if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_RSA) {
        tpmPublic->publicArea.type = TPM2_ALG_RSA;
        r = get_rsa_tpm2b_public_from_evp(publicKey, tpmPublic);
        goto_if_error(r, "Get public for RSA key.", cleanup);

    } else if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_EC) {
        tpmPublic->publicArea.type = TPM2_ALG_ECC;
        r = get_ecc_tpm2b_public_from_evp(publicKey, tpmPublic);
        goto_if_error(r, "Get public for ECC key.", cleanup);
    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong key_type", cleanup);
    }
cleanup:
    OSSL_FREE(publicKey, EVP_PKEY);
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
ifapi_verify_signature_quote(
    const IFAPI_OBJECT *keyObject,
    const uint8_t *signature,
    size_t signatureSize,
    const uint8_t *digest,
    size_t digestSize,
    const TPMT_SIG_SCHEME *signatureScheme)
{
    /* Check for NULL parameters */
    return_if_null(keyObject, "keyObject is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signatureScheme, "signatureScheme is NULL",
            TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r = TSS2_RC_SUCCESS;
    char *public_pem_key = NULL;
    int pem_size;
    EVP_PKEY *publicKey = NULL;
    BIO *bufio = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;

    /* Check whether or not the key is valid */
    if (keyObject->objectType == IFAPI_KEY_OBJ) {
        /* Compute public key */
        r = ifapi_pub_pem_key_from_tpm(&keyObject->misc.key.public, &public_pem_key,
                                       &pem_size);
        goto_if_error(r, "Compute public PEM key.", error_cleanup);
    } else if (keyObject->objectType == IFAPI_EXT_PUB_KEY_OBJ) {
        public_pem_key = strdup(keyObject->misc.ext_pub_key.pem_ext_public);
        check_oom(public_pem_key);
    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong object type",
                   error_cleanup);
    }

    /* Create an OpenSSL object for the key */
    bufio = BIO_new_mem_buf((void *)public_pem_key,
                            strlen(public_pem_key));
    goto_if_null(bufio, "BIO buffer could not be allocated.",
                 TSS2_FAPI_RC_MEMORY, error_cleanup);

    publicKey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    goto_if_null(publicKey, "PEM format could not be decoded.",
                 TSS2_FAPI_RC_BAD_VALUE, error_cleanup);

    /* Create the hash engine */
    if (!(mdctx = EVP_MD_CTX_create())) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP_MD_CTX_create",
                   error_cleanup);
    }

    const EVP_MD *hashAlgorithm = get_hash_md(signatureScheme->details.any.hashAlg);
    if (!hashAlgorithm) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid hash alg.",
                   error_cleanup);
    }

    /* Verify the digest of the signature */
    if (1 != EVP_DigestVerifyInit(mdctx, &pctx, hashAlgorithm, NULL, publicKey)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "EVP_DigestVerifyInit",
                   error_cleanup);
    }
    goto_if_null(pctx, "Out of memory", TSS2_FAPI_RC_MEMORY, error_cleanup);
    if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_RSA) {
        int padding = get_sig_scheme(signatureScheme->scheme);
        if (!padding) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Invalid padding scheme.", error_cleanup);
        }
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, padding)) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "EVP_PKEY_CTX_set_rsa_padding", error_cleanup);
        }
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, digest, digestSize)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "EVP_DigestVerifyUpdate", error_cleanup);
    }
    if (1 != EVP_DigestVerifyFinal(mdctx, signature, signatureSize)) {
        goto_error(r, TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED,
                   "EVP_DigestSignFinal", error_cleanup);
    }

error_cleanup:
    if (mdctx != NULL) {
        EVP_MD_CTX_destroy(mdctx);
    }
    SAFE_FREE(public_pem_key);
    EVP_PKEY_free(publicKey);
    BIO_free(bufio);
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
ifapi_verify_signature(
    const IFAPI_OBJECT *keyObject,
    const uint8_t *signature,
    size_t signatureSize,
    const uint8_t *digest,
    size_t digestSize)
{
    /* Check for NULL parameters */
    return_if_null(keyObject, "keyObject is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r = TSS2_RC_SUCCESS;
    char *public_pem_key = NULL;
    int pem_size;
    EVP_PKEY *publicKey = NULL;
    BIO *bufio = NULL;

    /* Check whether or not the key is valid */
    if (keyObject->objectType == IFAPI_KEY_OBJ) {
        /* Compute public key */
        r = ifapi_pub_pem_key_from_tpm(&keyObject->misc.key.public, &public_pem_key,
                                       &pem_size);
        goto_if_error(r, "Compute public PEM key.", error_cleanup);
    } else if (keyObject->objectType == IFAPI_EXT_PUB_KEY_OBJ) {
        public_pem_key = strdup(keyObject->misc.ext_pub_key.pem_ext_public);
        check_oom(public_pem_key);
    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong object type",
                   error_cleanup);
    }

    /* Convert the key to an OpenSSL object */
    bufio = BIO_new_mem_buf((void *)public_pem_key,
                                strlen(public_pem_key));
    goto_if_null(bufio, "Out of memory.", TSS2_FAPI_RC_MEMORY, error_cleanup);
    publicKey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    goto_if_null(publicKey, "PEM format could not be decoded.",
                 TSS2_FAPI_RC_MEMORY, error_cleanup);

    /* Call a suitable local function for the verification */
    if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_RSA) {
        r = rsa_verify_signature(publicKey, signature, signatureSize, digest,
                                     digestSize);
        goto_if_error(r, "Verify RSA signature.", error_cleanup);

    } else if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_EC) {
        r = ecdsa_verify_signature(publicKey, signature, signatureSize,
                                   digest, digestSize);
        goto_if_error(r, "Verify ECC signature", error_cleanup);

    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong key type",
                       error_cleanup);
    }

error_cleanup:
    SAFE_FREE(public_pem_key);
    EVP_PKEY_free(publicKey);
    if (bufio)
        BIO_free(bufio);
    return r;
}

/**
 * Returns the digest size of a given hash algorithm.
 *
 * @param[in] hashAlgorithm The TSS identifier of the hash algorithm
 *
 * @return The size of the digest produced by the hash algorithm if
 * hashAlgorithm is valid
 * @retval 0 if hashAlgorithm is invalid
 */
size_t
ifapi_hash_get_digest_size(TPM2_ALG_ID hashAlgorithm)
{
    switch (hashAlgorithm) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
        break;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
        break;
    default:
        return 0;
    }
}

/**
 * Converts a TSS hash algorithm identifier into an OpenSSL hash algorithm
 * identifier object.
 *
 * @param[in] hashAlgorithm The TSS hash algorithm identifier to convert
 *
 * @retval A suitable OpenSSL identifier object if one could be found
 * @retval NULL if no suitable identifier object could be found
 */
static const EVP_MD *
get_ossl_hash_md(TPM2_ALG_ID hashAlgorithm)
{
    switch (hashAlgorithm) {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
        break;
    case TPM2_ALG_SHA256:
        return EVP_sha256();
        break;
    case TPM2_ALG_SHA384:
        return EVP_sha384();
        break;
    case TPM2_ALG_SHA512:
        return EVP_sha512();
        break;
    default:
        return NULL;
    }
}

/**
 * Starts the computation of a hash digest.
 *
 * @param[out] context The created hash context (callee-allocated).
 * @param[in] hashAlgorithm The TSS hash identifier for the hash algorithm to use.
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_BAD_VALUE if hashAlgorithm is invalid
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if context is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory cannot be allocated
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 */
TSS2_RC
ifapi_crypto_hash_start(IFAPI_CRYPTO_CONTEXT_BLOB **context,
                        TPM2_ALG_ID hashAlgorithm)
{
    /* Check for NULL parameters */
    return_if_null(context, "context is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Initialize the hash context */
    TSS2_RC r = TSS2_RC_SUCCESS;
    LOG_DEBUG("call: context=%p hashAlg=%" PRIu16, context, hashAlgorithm);
    IFAPI_CRYPTO_CONTEXT *mycontext = NULL;
    mycontext = calloc(1, sizeof(IFAPI_CRYPTO_CONTEXT));
    return_if_null(mycontext, "Out of memory", TSS2_FAPI_RC_MEMORY);

    if (!(mycontext->osslHashAlgorithm = get_ossl_hash_md(hashAlgorithm))) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   hashAlgorithm);
    }

    if (!(mycontext->hashSize = ifapi_hash_get_digest_size(hashAlgorithm))) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   hashAlgorithm);
    }

    if (!(mycontext->osslContext = EVP_MD_CTX_create())) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Error EVP_MD_CTX_create",
                   cleanup);
    }

    if (1 != EVP_DigestInit_ex(mycontext->osslContext,
                               mycontext->osslHashAlgorithm, get_engine())) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Error EVP_DigestInit_ex",
                   cleanup);
    }

    *context = (IFAPI_CRYPTO_CONTEXT_BLOB *) mycontext;

    return TSS2_RC_SUCCESS;

cleanup:
    if (mycontext->osslContext)
        EVP_MD_CTX_destroy(mycontext->osslContext);
    SAFE_FREE(mycontext);

    return r;
}

/**
 * Updates the digest value of a hash object with data from a byte buffer.
 *
 * @param[in,out] context The hash context that will be updated
 * @param[in] buffer The data for the update
 * @param[in] size The size of data in bytes
 *
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 */
TSS2_RC
ifapi_crypto_hash_update(IFAPI_CRYPTO_CONTEXT_BLOB *context,
                         const uint8_t *buffer, size_t size)
{
    /* Check for NULL parameters */
    return_if_null(context, "context is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(buffer, "buffer is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    LOG_DEBUG("called for context %p, buffer %p and size %zd", context, buffer,
              size);

    /* Update the digest */
    IFAPI_CRYPTO_CONTEXT *mycontext = (IFAPI_CRYPTO_CONTEXT *) context;
    LOGBLOB_DEBUG(buffer, size, "Updating hash with");

    if (1 != EVP_DigestUpdate(mycontext->osslContext, buffer, size)) {
        return_error(TSS2_FAPI_RC_GENERAL_FAILURE, "OSSL hash update");
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Gets the digest value from a hash context and closes it.
 *
 * @param[in,out] context The hash context that is released
 * @param[out] digest The buffer for the digest value
 * @param[out] digestSize The size of digest in bytes. Can be NULL
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if context or digest is NULL
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 */
TSS2_RC
ifapi_crypto_hash_finish(IFAPI_CRYPTO_CONTEXT_BLOB **context,
                         uint8_t *digest, size_t *digestSize)
{
    /* Check for NULL parameters */
    return_if_null(context, "context is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    unsigned int computedDigestSize = 0;

    LOG_TRACE("called for context-pointer %p, digest %p and size-pointer %p",
              context, digest, digestSize);
    /* Compute the digest */
    IFAPI_CRYPTO_CONTEXT *mycontext = *context;
    if (1 != EVP_DigestFinal_ex(mycontext->osslContext, digest,
                                &computedDigestSize)) {
        return_error(TSS2_FAPI_RC_GENERAL_FAILURE, "OSSL error.");
    }

    if (computedDigestSize != mycontext->hashSize) {
        return_error(TSS2_FAPI_RC_GENERAL_FAILURE,
                     "Invalid size computed by EVP_DigestFinal_ex");
    }

    LOGBLOB_DEBUG(digest, mycontext->hashSize, "finish hash");

    if (digestSize != NULL) {
        *digestSize = mycontext->hashSize;
    }

    /* Finalize the hash context */
    EVP_MD_CTX_destroy(mycontext->osslContext);
    free(mycontext);
    *context = NULL;

    return TSS2_RC_SUCCESS;
}

/**
 * Aborts a hash operation and finalizes the hash context. It will be set to
 * NULL.
 *
 * @param[in,out] context The context of the digest object.
 */
void
ifapi_crypto_hash_abort(IFAPI_CRYPTO_CONTEXT_BLOB **context)
{
    LOG_TRACE("called for context-pointer %p", context);
    if (context == NULL || *context == NULL) {
        LOG_DEBUG("Null-Pointer passed");
        return;
    }
    IFAPI_CRYPTO_CONTEXT *mycontext = (IFAPI_CRYPTO_CONTEXT *) * context;

    EVP_MD_CTX_destroy(mycontext->osslContext);
    free(mycontext);
    *context = NULL;
}

/**
 * Get url to download crl from certificate.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_NO_CERT if an error did occur during certificate downloading.
 */
TSS2_RC
get_crl_from_cert(X509 *cert, X509_CRL **crl)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    unsigned char* url = NULL;
    unsigned char *crl_buffer = NULL;
    size_t crl_buffer_size;
    int nid = NID_crl_distribution_points;
    STACK_OF(DIST_POINT) * dist_points = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(cert, nid, NULL, NULL);
    int curl_rc;

    *crl = NULL;
    for (int i = 0; i < sk_DIST_POINT_num(dist_points); i++)
    {
        DIST_POINT *dp = sk_DIST_POINT_value(dist_points, i);
        DIST_POINT_NAME    *distpoint = dp->distpoint;
        if (distpoint->type==0)
        {
            for (int j = 0; j < sk_GENERAL_NAME_num(distpoint->name.fullname); j++)
            {
                GENERAL_NAME *gen_name = sk_GENERAL_NAME_value(distpoint->name.fullname, j);
                ASN1_IA5STRING *asn1_str = gen_name->d.uniformResourceIdentifier;
                SAFE_FREE(url);
                url = (unsigned char *)strdup((char *)asn1_str->data);
                goto_if_null2(url, "Out of memory", r, TSS2_FAPI_RC_MEMORY, cleanup);
            }
        }
    }

    curl_rc = ifapi_get_curl_buffer(url, &crl_buffer, &crl_buffer_size);
    if (curl_rc != 0) {
        goto_error(r, TSS2_FAPI_RC_NO_CERT, "Get crl.", cleanup);
    }

    OpenSSL_add_all_algorithms();

    unsigned const char* tmp_ptr1 = crl_buffer;
    unsigned const char** tmp_ptr2 = &tmp_ptr1;

    if (!d2i_X509_CRL(crl, tmp_ptr2, crl_buffer_size)) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Can't convert crl.", cleanup);
    }

cleanup:
    SAFE_FREE(crl_buffer);
    CRL_DIST_POINTS_free(dist_points);
    SAFE_FREE(url);
    return r;
}

/**
 * Converts a TPM certificate buffer to the PEM format.
 *
 * @param[in]  certBuffer A byte buffer holding the certificate
 * @param[in]  certBufferSize The size of certBuffer in bytes
 * @param[out] pemCert A byte buffer where the PEM-formatted certificate is
 *             stored
 * @param[out] certAlgorithmId The key type of the certified key
 * @param[out] tpmPublic The public key of the certificate in TPM format.
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if certBuffer or pemCert is NULL
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_RC_BAD_VALUE, if the certificate is invalid
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
TSS2_RC
ifapi_cert_to_pem(
    const uint8_t *certBuffer,
    size_t certBufferSize,
    char **pemCert,
    TPM2_ALG_ID *certAlgorithmId,
    TPM2B_PUBLIC *tpmPublic)
{
    /* Check for NULL parameters */
    return_if_null(certBuffer, "certBuffer is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(pemCert, "pemCert is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    TSS2_RC r = TSS2_RC_SUCCESS;
    X509 *cert = NULL;
    BIO *bio = NULL;
    EVP_PKEY *publicKey = NULL;
    int pemCertSize;

    if (!d2i_X509(&cert, (const unsigned char **)&certBuffer, certBufferSize)) {
        LOGBLOB_ERROR(certBuffer, certBufferSize, "Bad certificate data");
        return_error(TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid certificate.");
    }
    *pemCert = NULL;

    /* Memory IO will be used for OSSL key conversion */
    bio = BIO_new(BIO_s_mem());
    return_if_null(bio, "Out of memory.", TSS2_FAPI_RC_MEMORY);

    if (!PEM_write_bio_X509(bio, cert)) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "PEM_write_bio_X509", cleanup);
    }
    /* Determine the size of the data written */
    pemCertSize = BIO_get_mem_data(bio, pemCert);
    *pemCert = malloc(pemCertSize + 1);
    goto_if_null(pemCert, "Out of memory.", TSS2_FAPI_RC_MEMORY, cleanup);

    /* Get the byte buffer written to the BIO object */
    int readSize = BIO_read(bio, *pemCert, pemCertSize);
    if (readSize != pemCertSize) {
        SAFE_FREE(*pemCert);
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid BIO_read",
                   cleanup);
    }
    (*pemCert)[pemCertSize] = '\0';

    publicKey = X509_get_pubkey(cert);
    goto_if_null(publicKey, "No public key in certificate.",
                  TSS2_FAPI_RC_GENERAL_FAILURE, cleanup);

    if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_RSA) {
        tpmPublic->publicArea.type = TPM2_ALG_RSA;
        r = get_rsa_tpm2b_public_from_evp(publicKey, tpmPublic);
        goto_if_error(r, "Get public for RSA key.", cleanup);

    } else if (EVP_PKEY_type(EVP_PKEY_id(publicKey)) == EVP_PKEY_EC) {
        tpmPublic->publicArea.type = TPM2_ALG_ECC;
        r = get_ecc_tpm2b_public_from_evp(publicKey, tpmPublic);
        goto_if_error(r, "Get public for ECC key.", cleanup);
    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong key_type", cleanup);
    }

    if (certAlgorithmId != NULL) {
        switch (EVP_PKEY_id(publicKey)) {
        case EVP_PKEY_RSA:
            *certAlgorithmId = TPM2_ALG_RSA;
            break;
        case EVP_PKEY_EC:
            *certAlgorithmId = TPM2_ALG_ECC;
            break;
        default:
            goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong certificate (key type).",
                       cleanup);
        }
    }
cleanup:
    BIO_free(bio);
    OSSL_FREE(cert, X509);
    OSSL_FREE(publicKey, EVP_PKEY);
    return r;
}

/**
 * Returns a suitable hash algorithm for a given digest size.
 *
 * @param[in]  size The size of the digest
 * @param[out] hashAlgorithm A suitable hash algorithm for the digest size
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_REFERENCE if hashAlgorithm is NULL
 * @retval TSS2_FAPI_RC_BAD_VALUE if the digest size is invalid
 */
TSS2_RC
ifapi_get_hash_alg_for_size(uint16_t size, TPMI_ALG_HASH *hashAlgorithm)
{
    /* Check for NULL parameters */
    return_if_null(hashAlgorithm, "hashAlgorithm is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Determine the hash algorithm */
    switch (size) {
    case TPM2_SHA1_DIGEST_SIZE:
        *hashAlgorithm = TPM2_ALG_SHA1;
        return TSS2_RC_SUCCESS;
    case TPM2_SHA256_DIGEST_SIZE:
        *hashAlgorithm = TPM2_ALG_SHA256;
        return TSS2_RC_SUCCESS;
    case TPM2_SHA384_DIGEST_SIZE:
        *hashAlgorithm = TPM2_ALG_SHA384;
        return TSS2_RC_SUCCESS;
    case TPM2_SHA512_DIGEST_SIZE:
        *hashAlgorithm = TPM2_ALG_SHA512;
        return TSS2_RC_SUCCESS;
    default:
        return TSS2_FAPI_RC_BAD_VALUE;
    }
}

/** Convert PEM certificate to OSSL format.
 *
 * @param[in] pem_cert Certificate in PEM format.
 * @retval X509 OSSL certificate object.
 * @retval NULL If the conversion fails.
 */
static X509
*get_X509_from_pem(const char *pem_cert)
{
    if (!pem_cert) {
        return NULL;
    }
    BIO *bufio = NULL;
    X509 *cert = NULL;

    /* Use BIO for conversion */
    size_t pem_length = strlen(pem_cert);
    bufio = BIO_new_mem_buf((void *)pem_cert, pem_length);
    if (!bufio)
        return NULL;
    /* Convert the certificate */
    cert = PEM_read_bio_X509(bufio, NULL, NULL, NULL);
    BIO_free(bufio);
    return cert;
}

/** Get public information for key of a pem certificate.
 *
 * @param[in]  pem_cert The pem certificate.
 * @param[out] tpm_public The public information of the key in TPM format.
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_VALUE if the conversion fails.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if openssl errors occur.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_get_public_from_pem_cert(const char* pem_cert, TPM2B_PUBLIC *tpm_public)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    X509 *cert = NULL;
    EVP_PKEY *public_key = NULL;

    cert = get_X509_from_pem(pem_cert);
    return_if_null(cert, "Invalid certificate.", TSS2_FAPI_RC_BAD_VALUE);

    public_key = X509_get_pubkey(cert);
    goto_if_null(public_key, "No public key in certificate.",
                 TSS2_FAPI_RC_GENERAL_FAILURE, cleanup);

    if (EVP_PKEY_type(EVP_PKEY_id(public_key)) == EVP_PKEY_RSA) {
        tpm_public->publicArea.type = TPM2_ALG_RSA;
        r = get_rsa_tpm2b_public_from_evp(public_key, tpm_public);
        goto_if_error(r, "Get public for RSA key.", cleanup);

    } else if (EVP_PKEY_type(EVP_PKEY_id(public_key)) == EVP_PKEY_EC) {
        tpm_public->publicArea.type = TPM2_ALG_ECC;
        r = get_ecc_tpm2b_public_from_evp(public_key, tpm_public);
        goto_if_error(r, "Get public for ECC key.", cleanup);
    } else {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Wrong key_type", cleanup);
    }
cleanup:
    OSSL_FREE(cert, X509);
    OSSL_FREE(public_key, EVP_PKEY);
    return r;
}

/** Convert buffer from DER format to X509 certificate.
 *
 * @param[in] cert_buffer Certificate in DER format.
 * @aparm[in] cert_buffer_size Size of DER certificate.
 * @retval X509 OSSL certificate object.
 * @retval NULL If the conversion fails.
 */
static X509
*get_cert_from_buffer(unsigned char *cert_buffer, size_t cert_buffer_size)
{
    unsigned char *buffer = cert_buffer;
    X509 *cert = NULL;

    unsigned const char* tmp_ptr1 = buffer;
    unsigned const char** tmp_ptr2 = &tmp_ptr1;

    if (!d2i_X509(&cert, tmp_ptr2, cert_buffer_size))
        return NULL;
    return cert;
}

/**
 * Verify EK certificate read from TPM.
 *
 * @param[in] root_cert_pem The vendor root certificate.
 * @param[in] intermed_cert_pem The vendor intermediate certificate.
 * @param[in] ek_cert_pem The ek certificate from TPM.
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_BAD_VALUE if the verification was no successful.
 * @retval TSS2_FAPI_RC_NO_CERT if an error did occur during certificate downloading.
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an internal error occurred.
 * @retval TSS2_FAPI_RC_MEMORY if not enough memory can be allocated.
 */
TSS2_RC
ifapi_verify_ek_cert(
    char* root_cert_pem,
    char* intermed_cert_pem,
    char* ek_cert_pem)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    X509 *root_cert = NULL;
    X509 *intermed_cert = NULL;
    X509 *ek_cert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_CRL *crl_intermed = NULL;
    X509_CRL *crl_ek = NULL;
    int i;
    size_t ui;
    AUTHORITY_INFO_ACCESS *info = NULL;
    ASN1_IA5STRING *uri = NULL;
    unsigned char * url;
    unsigned char *cert_buffer = NULL;
    size_t cert_buffer_size;
    int curl_rc;

    ek_cert = get_X509_from_pem(ek_cert_pem);
    goto_if_null2(ek_cert, "Failed to convert PEM certificate to DER.",
                  r, TSS2_FAPI_RC_BAD_VALUE, cleanup);

    if (intermed_cert_pem) {
        intermed_cert = get_X509_from_pem(intermed_cert_pem);
        goto_if_null2(intermed_cert, "Failed to convert PEM certificate to DER.",
                      r, TSS2_FAPI_RC_BAD_VALUE, cleanup);
    } else {
        /* Get uri for ek intermediate certificate. */
        OpenSSL_add_all_algorithms();
        info = X509_get_ext_d2i(ek_cert, NID_info_access, NULL, NULL);

        for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
            ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
            if (ad->location->type != GEN_URI) {
                continue;
            }
            uri = ad->location->d.uniformResourceIdentifier;
            url = uri->data;
            curl_rc = ifapi_get_curl_buffer(url, &cert_buffer, &cert_buffer_size);
            if (curl_rc != 0) {
                goto_error(r, TSS2_FAPI_RC_NO_CERT, "Get certificate.", cleanup);
            }
            goto_if_null2(cert_buffer, "No certificate downloaded", r,
                          TSS2_FAPI_RC_NO_CERT, cleanup);
        }
        goto_if_null2(cert_buffer, "No certificate downloaded", r,
                      TSS2_FAPI_RC_NO_CERT, cleanup);

        OpenSSL_add_all_algorithms();
        intermed_cert = get_cert_from_buffer(cert_buffer, cert_buffer_size);

        SAFE_FREE(cert_buffer);
        goto_if_null2(intermed_cert, "Failed to create intermediate certificate.",
                      r, TSS2_FAPI_RC_GENERAL_FAILURE, cleanup);

         /* Get Certificate revocation list for Intermediate certificate */
        r = get_crl_from_cert(intermed_cert, &crl_intermed);
        goto_if_error(r, "Get crl for intermediate certificate.", cleanup);

        /* Get Certificate revocation list for EK certificate */
        r = get_crl_from_cert(ek_cert, &crl_ek);
        goto_if_error(r, "Get crl for ek certificate.", cleanup);
    }

    /* Prepare X509 certificate store */

    store = X509_STORE_new();

    goto_if_null2(store, "Failed to create X509 store.",
                  r, TSS2_FAPI_RC_GENERAL_FAILURE, cleanup);

    /* Add Certificate revocation list for EK certificate if one exists. */
    if (crl_ek) {
        /* Set the flags of the store to use CRLs. */
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        if (1 != X509_STORE_add_crl(store, crl_ek)) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Failed to add intermediate crl.", cleanup);
        }
    }

    /* Add Certificate revocation list for intermediate certificate if one exists. */
    if (crl_intermed) {
        /* Set the flags of the store to use CRLs. */
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        if (1 != X509_STORE_add_crl(store, crl_intermed)) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Failed to add intermediate crl.", cleanup);
        }
    }

    /* Add stored root certificates */
    for (ui = 0; ui < sizeof(root_cert_list) / sizeof(char *); ui++) {
         root_cert = get_X509_from_pem(root_cert_list[ui]);
         goto_if_null2(root_cert, "Failed to convert PEM certificate to DER.",
                       r, TSS2_FAPI_RC_BAD_VALUE, cleanup);
         if (1 != X509_STORE_add_cert(store, root_cert)) {
             goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                        "Failed to add root certificate", cleanup);
        }
        OSSL_FREE(root_cert, X509);
    }

    /* Create root cert if passed as parameter */
    if (root_cert_pem) {
        root_cert = get_X509_from_pem(root_cert_pem);
        goto_if_null2(root_cert, "Failed to convert PEM certificate to DER.",
                      r, TSS2_FAPI_RC_BAD_VALUE, cleanup);

        if (1 != X509_STORE_add_cert(store, root_cert)) {
            goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                       "Failed to add root certificate", cleanup);
        }
        OSSL_FREE(root_cert, X509);
    }

    /* Verify intermediate certificate */
    ctx = X509_STORE_CTX_new();
    goto_if_null2(ctx, "Failed to create X509 store context.",
                  r, TSS2_FAPI_RC_GENERAL_FAILURE, cleanup);
    if (1 != X509_STORE_CTX_init(ctx, store, intermed_cert, NULL)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Failed to initialize X509 context.", cleanup);
    }
    if (1 != X509_verify_cert(ctx)) {
        int rc = X509_STORE_CTX_get_error(ctx);
        LOG_ERROR("%s", X509_verify_cert_error_string(rc));
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Failed to verify EK certificate", cleanup);
    }
    if (1 != X509_STORE_add_cert(store, intermed_cert)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Failed to add intermediate certificate", cleanup);
    }

    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    ctx = X509_STORE_CTX_new();
    goto_if_null2(ctx, "Failed to create X509 store context.",
                  r, TSS2_FAPI_RC_GENERAL_FAILURE, cleanup);

    if (1 != X509_STORE_CTX_init(ctx, store, ek_cert, NULL)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Failed to initialize X509 context.", cleanup);
    }
    /* Verify the EK certificate. */
    if (1 != X509_verify_cert(ctx)) {
        int rc = X509_STORE_CTX_get_error(ctx);
        LOG_ERROR("%s", X509_verify_cert_error_string(rc));
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE,
                   "Failed to verify EK certificate", cleanup);
    }

cleanup:
    if (ctx) {
        X509_STORE_CTX_cleanup(ctx);
        X509_STORE_CTX_free(ctx);
    }
    if (store)
        X509_STORE_free(store);
    OSSL_FREE(root_cert, X509);
    OSSL_FREE(intermed_cert, X509);
    OSSL_FREE(ek_cert, X509);
    OSSL_FREE(crl_intermed, X509_CRL);
    OSSL_FREE(crl_ek, X509_CRL);
    OSSL_FREE(info, AUTHORITY_INFO_ACCESS);
    return r;
}

/** Compute the fingerprint of a TPM public key.
 *
 * @param[in] tpmPublicKey The public key created by the TPM
 * @param[in] hashAlg The hash algorithm used for fingerprint computation.
 * @param[out] fingerprint The fingerprint digest.
 *
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_FAPI_RC_GENERAL_FAILURE if an error occurs in the crypto library
 * @retval TSS2_FAPI_RC_MEMORY if memory could not be allocated
 * @retval TSS2_FAPI_BAD_REFERENCE if tpmPublicKey or pemKeySize are NULL
 * @retval TSS2_FAPI_RC_BAD_REFERENCE a invalid null pointer is passed.
 * @retval TSS2_FAPI_RC_BAD_VALUE if an invalid value was passed into
 *         the function.
 */
TSS2_RC
ifapi_get_tpm_key_fingerprint(
    const TPM2B_PUBLIC *tpmPublicKey,
    TPMI_ALG_HASH hashAlg,
    TPM2B_DIGEST *fingerprint)
{
    /* Check for NULL parameters */
    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    EVP_PKEY *evpPublicKey = NULL;
    TSS2_RC r = TPM2_RC_SUCCESS;
    uint8_t *pubKeyDer = NULL;
    int pubKeyDerSize;
    IFAPI_CRYPTO_CONTEXT_BLOB *cryptoContext = NULL;
    size_t hashSize;
    size_t fingerPrintSize;

    if (!(hashSize = ifapi_hash_get_digest_size(hashAlg))) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE,
                   "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   hashAlg);
    }

    evpPublicKey = EVP_PKEY_new();
    goto_if_null2(evpPublicKey, "Out of memory.", r, TSS2_FAPI_RC_MEMORY, cleanup);

    if (tpmPublicKey->publicArea.type == TPM2_ALG_RSA) {
        r = ossl_rsa_pub_from_tpm(tpmPublicKey, evpPublicKey);
    } else if (tpmPublicKey->publicArea.type == TPM2_ALG_ECC)
        r = ossl_ecc_pub_from_tpm(tpmPublicKey, evpPublicKey);
    else {
        goto_error(r,TSS2_FAPI_RC_BAD_VALUE, "Invalid alg id.", cleanup);
    }
    goto_if_error(r, "Get ossl public key.", cleanup);

    /* Convert the OpenSSL EVP pub key into DEF format */
    pubKeyDerSize = i2d_PUBKEY(evpPublicKey, &pubKeyDer);
    if (pubKeyDerSize == -1) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "OSSL error", cleanup);
    }

    /* Compute the digest of the DER public key */
    r = ifapi_crypto_hash_start(&cryptoContext, hashAlg);
    goto_if_error(r, "crypto hash start", cleanup);

    HASH_UPDATE_BUFFER(cryptoContext,
                       pubKeyDer, pubKeyDerSize, r, cleanup);
    r = ifapi_crypto_hash_finish(&cryptoContext,
                                 &fingerprint->buffer[0], &fingerPrintSize);
    goto_if_error(r, "crypto hash finish", cleanup);

    fingerprint->size = fingerPrintSize;

cleanup:
    EVP_PKEY_free(evpPublicKey);
    SAFE_FREE(pubKeyDer);
    if (cryptoContext) {
        ifapi_crypto_hash_abort(&cryptoContext);
    }
    return r;
}
