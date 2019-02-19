/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#define _GNU_SOURCE

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <stdio.h>

#include "tss2_esys.h"

#include "esys_crypto.h"
#include "esys_crypto_ossl.h"

#include "esys_iutil.h"
#include "esys_mu.h"
#define LOGMODULE esys
#include "util/log.h"
#include "util/aux_util.h"
#include "esys_crypto_ossl.h"

static ENGINE *engine = NULL;

ENGINE *get_engine()
{
    if (engine)
        return engine;
    engine = ENGINE_by_id("openssl");
    return engine;
}

static int
iesys_bn2binpad(const BIGNUM *bn, unsigned char *bin, int bin_length)
{
    int len_bn = BN_num_bytes(bn);
    int offset = bin_length - len_bn;
    memset(bin,0,offset);
    BN_bn2bin(bn, bin + offset);
    return 1;
}

/** Context to hold temporary values for iesys_crypto */
typedef struct _IESYS_CRYPTO_CONTEXT {
    enum {
        IESYS_CRYPTOSSL_TYPE_HASH = 1,
        IESYS_CRYPTOSSL_TYPE_HMAC,
    } type; /**< The type of context to hold; hash or hmac */
    union {
        struct {
            EVP_MD_CTX  *ossl_context;
            const EVP_MD *ossl_hash_alg;
            size_t hash_len;
        } hash; /**< the state variables for a hash context */
        struct {
            EVP_MD_CTX *ossl_context;
            const EVP_MD *ossl_hash_alg;
            size_t hmac_len;
        } hmac; /**< the state variables for an hmac context */
    };
} IESYS_CRYPTOSSL_CONTEXT;

size_t
hash_get_digest_size(TPM2_ALG_ID hashAlg)
{
    switch (hashAlg) {
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

const EVP_MD *
get_ossl_hash_md(TPM2_ALG_ID hashAlg)
{
    switch (hashAlg) {
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
iesys_cryptossl_hash_start(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                           TPM2_ALG_ID hashAlg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    LOG_TRACE("call: context=%p hashAlg=%"PRIu16, context, hashAlg);
    return_if_null(context, "Context is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(context, "Null-Pointer passed for context", TSS2_ESYS_RC_BAD_REFERENCE);
    IESYS_CRYPTOSSL_CONTEXT *mycontext;
    mycontext = calloc(1, sizeof(IESYS_CRYPTOSSL_CONTEXT));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);
    mycontext->type = IESYS_CRYPTOSSL_TYPE_HASH;

    if (!(mycontext->hash.ossl_hash_alg = get_ossl_hash_md(hashAlg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%"PRIu16")", cleanup, hashAlg);
    }

    if (!(mycontext->hash.hash_len = hash_get_digest_size(hashAlg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%"PRIu16")", cleanup, hashAlg);
    }

    if (!(mycontext->hash.ossl_context =  EVP_MD_CTX_create())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Error EVP_MD_CTX_create", cleanup);
    }

    if (1 != EVP_DigestInit_ex(mycontext->hash.ossl_context,
                               mycontext->hash.ossl_hash_alg,
                               get_engine())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Errror EVP_DigestInit_ex", cleanup);
    }

    *context = (IESYS_CRYPTO_CONTEXT_BLOB *) mycontext;

    return TSS2_RC_SUCCESS;

 cleanup:
    if (mycontext->hash.ossl_context)
        EVP_MD_CTX_destroy(mycontext->hash.ossl_context);
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
iesys_cryptossl_hash_update(IESYS_CRYPTO_CONTEXT_BLOB * context,
                            const uint8_t * buffer, size_t size)
{
    LOG_TRACE("called for context %p, buffer %p and size %zd", context, buffer,
              size);
    if (context == NULL || buffer == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOSSL_CONTEXT *mycontext = (IESYS_CRYPTOSSL_CONTEXT *) context;
    if (mycontext->type != IESYS_CRYPTOSSL_TYPE_HASH) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    LOGBLOB_TRACE(buffer, size, "Updating hash with");

    if (1 != EVP_DigestUpdate(mycontext->hash.ossl_context, buffer, size)) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "OSSL hash update");
    }

    return TSS2_RC_SUCCESS;
}

/** Update the digest value of a digest object from a TPM2B object.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm of the context.
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] b The TPM2B object for the update.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 */
TSS2_RC
iesys_cryptossl_hash_update2b(IESYS_CRYPTO_CONTEXT_BLOB * context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret = iesys_cryptossl_hash_update(context, &b->buffer[0], b->size);
    return ret;
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
iesys_cryptossl_hash_finish(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                            uint8_t * buffer, size_t * size)
{
    unsigned int digest_size = 0;

    LOG_TRACE("called for context-pointer %p, buffer %p and size-pointer %p",
              context, buffer, size);
    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTOSSL_CONTEXT *mycontext = * context;
    if (mycontext->type != IESYS_CRYPTOSSL_TYPE_HASH) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    if (*size < mycontext->hash.hash_len) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "Buffer too small");
    }

    if (1 != EVP_DigestFinal_ex(mycontext->hash.ossl_context, buffer, &digest_size)) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "Ossl error.");
    }

    if (digest_size != mycontext->hash.hash_len) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE,
                     "Invalid size computed by EVP_DigestFinal_ex");
    }

    LOGBLOB_TRACE(buffer, mycontext->hash.hash_len, "read hash result");

    *size = mycontext->hash.hash_len;
    EVP_MD_CTX_destroy(mycontext->hash.ossl_context);
    free(mycontext);
    *context = NULL;

    return TSS2_RC_SUCCESS;
}

/** Release the resources of a digest object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the digest object.
 */
void
iesys_cryptossl_hash_abort(IESYS_CRYPTO_CONTEXT_BLOB ** context)
{
    LOG_TRACE("called for context-pointer %p", context);
    if (context == NULL || *context == NULL) {
        LOG_DEBUG("Null-Pointer passed");
        return;
    }
    IESYS_CRYPTOSSL_CONTEXT *mycontext =
        (IESYS_CRYPTOSSL_CONTEXT *) * context;
    if (mycontext->type != IESYS_CRYPTOSSL_TYPE_HASH) {
        LOG_DEBUG("bad context");
        return;
    }

    EVP_MD_CTX_destroy(mycontext->hash.ossl_context);
    free(mycontext);
    *context = NULL;
}

/* HMAC */

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
iesys_cryptossl_hmac_start(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                           TPM2_ALG_ID hashAlg,
                           const uint8_t * key, size_t size)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    EVP_PKEY *hkey = NULL;

    LOG_TRACE("called for context-pointer %p and hmacAlg %d", context, hashAlg);
    LOGBLOB_TRACE(key, size, "Starting  hmac with");
    if (context == NULL || key == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE,
                     "Null-Pointer passed in for context");
    }
    IESYS_CRYPTOSSL_CONTEXT *mycontext = calloc(1, sizeof(IESYS_CRYPTOSSL_CONTEXT));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);

    if (!(mycontext->hmac.ossl_hash_alg = get_ossl_hash_md(hashAlg))) {
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "Unsupported hash algorithm (%"PRIu16")", cleanup, hashAlg);
    }

    if (!(mycontext->hmac.hmac_len = hash_get_digest_size(hashAlg))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Unsupported hash algorithm (%"PRIu16")", cleanup, hashAlg);
    }

    if (!(mycontext->hmac.ossl_context =  EVP_MD_CTX_create())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Error EVP_MD_CTX_create", cleanup);
    }

    if (!(hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, get_engine(), key, size))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "EVP_PKEY_new_mac_key", cleanup);
    }

    if(1 != EVP_DigestSignInit(mycontext->hmac.ossl_context, NULL,
                               mycontext->hmac.ossl_hash_alg, get_engine(), hkey)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "DigestSignInit", cleanup);
    }

    mycontext->type = IESYS_CRYPTOSSL_TYPE_HMAC;

    *context = (IESYS_CRYPTO_CONTEXT_BLOB *) mycontext;

    EVP_PKEY_free(hkey);

    return TSS2_RC_SUCCESS;

 cleanup:
    if (mycontext->hmac.ossl_context)
        EVP_MD_CTX_destroy(mycontext->hmac.ossl_context);
    if(hkey)
        EVP_PKEY_free(hkey);
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
iesys_cryptossl_hmac_update(IESYS_CRYPTO_CONTEXT_BLOB * context,
                            const uint8_t * buffer, size_t size)
{
    LOG_TRACE("called for context %p, buffer %p and size %zd",
              context, buffer, size);
    if (context == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTOSSL_CONTEXT *mycontext = (IESYS_CRYPTOSSL_CONTEXT *) context;
    if (mycontext->type != IESYS_CRYPTOSSL_TYPE_HMAC) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    LOGBLOB_TRACE(buffer, size, "Updating hmac with");

    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mycontext->hmac.ossl_context, buffer, size)) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "OSSL HMAC update");
    }

    return TSS2_RC_SUCCESS;
}

/** Update and HMAC digest value from a TPM2B object.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm and the key of the context.
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] b The TPM2B object for the update.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 */
TSS2_RC
iesys_cryptossl_hmac_update2b(IESYS_CRYPTO_CONTEXT_BLOB * context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    TSS2_RC ret = iesys_cryptossl_hmac_update(context, &b->buffer[0], b->size);
    return ret;
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
iesys_cryptossl_hmac_finish(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                            uint8_t * buffer, size_t * size)
{

    TSS2_RC r = TSS2_RC_SUCCESS;

    LOG_TRACE("called for context-pointer %p, buffer %p and size-pointer %p",
              context, buffer, size);
    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTOSSL_CONTEXT *mycontext =
        (IESYS_CRYPTOSSL_CONTEXT *) * context;
    if (mycontext->type != IESYS_CRYPTOSSL_TYPE_HMAC) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    if (*size < mycontext->hmac.hmac_len) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "Buffer too small");
    }

    if (1 != EVP_DigestSignFinal(mycontext->hmac.ossl_context, buffer, size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "DigestSignFinal", cleanup);
    }

    LOGBLOB_TRACE(buffer, *size, "read hmac result");

 cleanup:
    EVP_MD_CTX_destroy(mycontext->hmac.ossl_context);
    SAFE_FREE(mycontext);
    *context = NULL;
    return r;
}

/** Write the HMAC digest value to a TPM2B object and close the context.
 *
 * The digest value will written to a passed TPM2B object and the resources of
 * the HMAC object are released.
 * @param[in,out] context The context of the HMAC object.
 * @param[out] hmac The buffer for the digest value (caller-allocated).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_ESYS_RC_BAD_SIZE if the size passed is lower than the HMAC length.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptossl_hmac_finish2b(IESYS_CRYPTO_CONTEXT_BLOB ** context, TPM2B * hmac)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, hmac);
    if (context == NULL || *context == NULL || hmac == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    size_t s = hmac->size;
    TSS2_RC ret = iesys_cryptossl_hmac_finish(context, &hmac->buffer[0], &s);
    hmac->size = s;
    return ret;
}

/** Release the resources of an HAMC object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the HMAC object.
 */
void
iesys_cryptossl_hmac_abort(IESYS_CRYPTO_CONTEXT_BLOB ** context)
{
    LOG_TRACE("called for context-pointer %p", context);
    if (context == NULL || *context == NULL) {
        LOG_DEBUG("Null-Pointer passed");
        return;
    }
    if (*context != NULL) {
        IESYS_CRYPTOSSL_CONTEXT *mycontext =
            (IESYS_CRYPTOSSL_CONTEXT *) * context;
        if (mycontext->type != IESYS_CRYPTOSSL_TYPE_HMAC) {
            LOG_DEBUG("bad context");
            return;
        }

        EVP_MD_CTX_destroy(mycontext->hmac.ossl_context);

        free(mycontext);
        *context = NULL;
    }
}

/** Compute random TPM2B data.
 *
 * The random data will be generated and written to a passed TPM2B structure.
 * @param[out] nonce The TPM2B structure for the random data (caller-allocated).
 * @param[in] num_bytes The number of bytes to be generated.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
iesys_cryptossl_random2b(TPM2B_NONCE * nonce, size_t num_bytes)
{
    if (num_bytes == 0) {
        nonce->size = sizeof(TPMU_HA);
    } else {
        nonce->size = num_bytes;
    }
    if (1 != RAND_bytes(&nonce->buffer[0], nonce->size)) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE,
                     "Failure in random number generator.");
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
iesys_cryptossl_pk_encrypt(TPM2B_PUBLIC * pub_tpm_key,
                           size_t in_size,
                           BYTE * in_buffer,
                           size_t max_out_size,
                           BYTE * out_buffer,
                           size_t * out_size, const char *label)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    const EVP_MD * hashAlg = NULL;
    RSA * rsa_key = NULL;
    EVP_PKEY *evp_rsa_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM* bne = NULL;
    int padding;
    char *label_copy = NULL;

    if (!(hashAlg = get_ossl_hash_md(pub_tpm_key->publicArea.nameAlg))) {
        LOG_ERROR("Unsupported hash algorithm (%"PRIu16")",
                  pub_tpm_key->publicArea.nameAlg);
        return TSS2_ESYS_RC_NOT_IMPLEMENTED;
    }

    if (!(bne = BN_new())) {
        goto_error(r, TSS2_ESYS_RC_MEMORY,
                   "Could not allocate Big Number", cleanup);
    }

    switch (pub_tpm_key->publicArea.parameters.rsaDetail.scheme.scheme) {
    case TPM2_ALG_NULL:
        padding = RSA_NO_PADDING;
        break;
    case TPM2_ALG_RSAES:
        padding = RSA_PKCS1_PADDING;
        break;
    case TPM2_ALG_OAEP:
        padding = RSA_PKCS1_OAEP_PADDING;
        break;
    default:
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE, "Illegal RSA scheme", cleanup);
    }

    UINT32 exp;
    if (pub_tpm_key->publicArea.parameters.rsaDetail.exponent == 0)
        exp = 65537;
    else
        exp = pub_tpm_key->publicArea.parameters.rsaDetail.exponent;
    if (1 != BN_set_word(bne, exp)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set exponent.", cleanup);
    }

    if (!(rsa_key = RSA_new())) {
        goto_error(r, TSS2_ESYS_RC_MEMORY,
                   "Could not allocate RSA key", cleanup);
    }

    if (1 != RSA_generate_key_ex(rsa_key,
                                 pub_tpm_key->publicArea.parameters.rsaDetail.keyBits,
                                 bne, NULL)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Could not generate RSA key",
                   cleanup);
    }

    if (!(evp_rsa_key = EVP_PKEY_new())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not create evp key.", cleanup);
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (!BN_bin2bn(pub_tpm_key->publicArea.unique.rsa.buffer,
                           pub_tpm_key->publicArea.unique.rsa.size,
                           rsa_key->n)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not create rsa n.", cleanup);
    }
#else
    BIGNUM *n = NULL;
    if (!(n = BN_bin2bn(pub_tpm_key->publicArea.unique.rsa.buffer,
                        pub_tpm_key->publicArea.unique.rsa.size,
                        NULL))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not create rsa n.", cleanup);
    }

    if (1 != RSA_set0_key(rsa_key, n, NULL, NULL)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set rsa n.", cleanup);
    }
#endif

    if (1 != EVP_PKEY_set1_RSA(evp_rsa_key, rsa_key)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set rsa key.", cleanup);
    }

    if (!(ctx = EVP_PKEY_CTX_new(evp_rsa_key, get_engine()))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not create evp context.", cleanup);
    }

    if (1 != EVP_PKEY_encrypt_init(ctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not init encrypt context.", cleanup);
    }

    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, padding)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set RSA passing.", cleanup);
    }

    label_copy = OPENSSL_strdup(label);
    if (!label_copy) {
        goto_error(r, TSS2_ESYS_RC_MEMORY,
                   "Could not duplicate OAEP label", cleanup);
    }

    if (1 != EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label_copy, strlen(label_copy)+1)) {
        OPENSSL_free(label_copy);
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set RSA label.", cleanup);
    }

    if (1 != EVP_PKEY_CTX_set_rsa_oaep_md(ctx, hashAlg)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set hash algorithm.", cleanup);
    }

    /* Determine out size */
    if (1 != EVP_PKEY_encrypt(ctx, NULL, out_size, in_buffer, in_size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not determine ciper size.", cleanup);
    }

    if ((size_t)*out_size > max_out_size) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Encrypted data too big", cleanup);
    }

    /* Encrypt data */
    if (1 != EVP_PKEY_encrypt(ctx, out_buffer, out_size, in_buffer, in_size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not encrypt data.", cleanup);
    }

    r = TSS2_RC_SUCCESS;

 cleanup:
    OSSL_FREE(ctx, EVP_PKEY_CTX);
    OSSL_FREE(evp_rsa_key, EVP_PKEY);
    OSSL_FREE(rsa_key, RSA);
    OSSL_FREE(bne, BN);
    return r;
}

/** Computation of OSSL ec public point from TPM public point.
 *
 * @param[in] group The definition of the used ec curve.
 * @param[in] key The TPM public key.
 * @param[out] The TPM's public point in OSSL format.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE The internal crypto engine failed.
 */
TSS2_RC
tpm_pub_to_ossl_pub(EC_GROUP *group, TPM2B_PUBLIC *key, EC_POINT **tpm_pub_key)
{

    TSS2_RC r = TSS2_RC_SUCCESS;
    BIGNUM *bn_x = NULL;
    BIGNUM *bn_y = NULL;
    BN_CTX *bctx = NULL;

    bctx = BN_CTX_new();

    /* Create the big numbers for the coordinates of the point */
    if (!(bn_x = BN_bin2bn(&key->publicArea.unique.ecc.x.buffer[0],
                           key->publicArea.unique.ecc.x.size,
                           NULL))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Create big num from byte buffer.", cleanup);
    }

    if (!(bn_y = BN_bin2bn(&key->publicArea.unique.ecc.y.buffer[0],
                           key->publicArea.unique.ecc.y.size,
                           NULL))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Create big num from byte buffer.", cleanup);
    }

    /* Create the ec point with the affine coordinates of the TPM point */
    if (!(*tpm_pub_key = EC_POINT_new(group))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Create point.", cleanup);
    }

    if (1 != EC_POINT_set_affine_coordinates_GFp(group,
                                                 *tpm_pub_key, bn_x,
                                                 bn_y, bctx)) {
        OSSL_FREE(*tpm_pub_key, EC_POINT);
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Set affine coordinates", cleanup);
    }

    if (1 != EC_POINT_is_on_curve(group, *tpm_pub_key, bctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "The TPM point is not on the curve", cleanup);
    }

 cleanup:
    OSSL_FREE(bn_x, BN);
    OSSL_FREE(bn_y, BN);
    OSSL_FREE(bctx, BN_CTX);

    return r;
}

/** Computation of ephemeral ECC key and shared secret Z.
 *
 * According to the description in  TPM spec part 1 C 6.1 a shared secret
 * between application and TPM is computed (ECDH). An ephemeral ECC key and a
 * TPM keyare used for the ECDH key exchange.
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
iesys_cryptossl_get_ecdh_point(TPM2B_PUBLIC *key,
                               size_t max_out_size,
                               TPM2B_ECC_PARAMETER *Z,
                               TPMS_ECC_POINT *Q,
                               BYTE * out_buffer,
                               size_t * out_size)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    BN_CTX *bctx = NULL;                  /* Context used for big number operations */
    EC_GROUP *group = NULL;               /* Group defines the used curve */
    EC_KEY *eph_ec_key = NULL;            /* Ephemeral ec key of application */
    const EC_POINT *eph_pub_key = NULL;   /* Public part of ephemeral key */
    EC_POINT *tpm_pub_key = NULL;         /* Public part of TPM key */
    EC_POINT *mul_eph_tpm = NULL;
    BIGNUM *bn_x = NULL;
    BIGNUM *bn_y = NULL;
    size_t key_size;
    int curveId;
    size_t offset;

    /* Set ossl constant for curve type and create group for curve */
    switch (key->publicArea.parameters.eccDetail.curveID) {
    case TPM2_ECC_NIST_P192:
        curveId = NID_X9_62_prime192v1;
        key_size = 24;
        break;
    case TPM2_ECC_NIST_P224:
        curveId = NID_secp224r1;
        key_size = 38;
        break;
    case TPM2_ECC_NIST_P256:
        curveId = NID_X9_62_prime256v1;
        key_size = 32;
        break;
    case TPM2_ECC_NIST_P384:
        curveId = NID_secp384r1;
        key_size = 48;
        break;
    case TPM2_ECC_NIST_P521:
        curveId = NID_secp521r1;
        key_size = 66;
        break;
    default:
        return_error(TSS2_ESYS_RC_NOT_IMPLEMENTED,
                     "ECC curve not implemented.");
    }

    if (!(group = EC_GROUP_new_by_curve_name(curveId))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Create group for curve", cleanup);
    }

    /* Create ephemeral key */
    if (!(eph_ec_key = EC_KEY_new())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Create ec key", cleanup);
    }
    if (1 !=   EC_KEY_set_group(eph_ec_key , group)) {

        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Set group", cleanup);
    }

    if (1 != EC_KEY_generate_key(eph_ec_key)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Generate ec key", cleanup);
    }

    if (!(eph_pub_key =  EC_KEY_get0_public_key(eph_ec_key))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Get public key", cleanup);
    }

    if (1 != EC_POINT_is_on_curve(group, eph_pub_key, bctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Ephemeral public key is on curve",cleanup);
    }

    /* Write affine coordinates of ephemeral pub key to TPM point Q */
    if (!(bctx = BN_CTX_new())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Create bignum context", cleanup);
    }

    if (!(bn_x = BN_new())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create bignum", cleanup);
    }

    if (!(bn_y = BN_new())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create bignum", cleanup);
    }

    if (1 != EC_POINT_get_affine_coordinates_GFp(group, eph_pub_key, bn_x,
                                                 bn_y, bctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Get affine x coordinate", cleanup);
    }

    if (1 != iesys_bn2binpad(bn_x, &Q->x.buffer[0], key_size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Write big num byte buffer", cleanup);
    }

    if (1 != iesys_bn2binpad(bn_y, &Q->y.buffer[0], key_size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Write big num byte buffer", cleanup);
    }

    Q->x.size = key_size;
    Q->y.size = key_size;

    /* Create an OSSL EC point from the TPM public point */
    r = tpm_pub_to_ossl_pub(group, key, &tpm_pub_key);
    goto_if_error(r, "Convert TPM pub point to ossl pub point", cleanup);

    /* Multiply the ephemeral private key with TPM public key */
    const BIGNUM * eph_priv_key = EC_KEY_get0_private_key(eph_ec_key);

    if (!(mul_eph_tpm = EC_POINT_new(group))) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create point.", cleanup);
    }

    if (1 != EC_POINT_mul(group, mul_eph_tpm, NULL,
                          tpm_pub_key, eph_priv_key, bctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "ec point multiplication", cleanup);
    }

    /* Write the x-part of the affine coordinate to Z */
    if (1 != EC_POINT_get_affine_coordinates_GFp(group, mul_eph_tpm, bn_x,
                                                 bn_y, bctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Get affine x coordinate", cleanup);
    }

    if (1 != iesys_bn2binpad(bn_x, &Z->buffer[0], key_size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Write big num byte buffer", cleanup);
    }

    Z->size = key_size;

    /* Write the public ephemeral key in TPM format to out buffer */
    offset = 0;
    r = Tss2_MU_TPMS_ECC_POINT_Marshal(Q,  &out_buffer[0], max_out_size, &offset);
    goto_if_error(r, "Error marshaling", cleanup);
    *out_size = offset;

 cleanup:
    OSSL_FREE(mul_eph_tpm, EC_POINT);
    OSSL_FREE(tpm_pub_key, EC_POINT);
    OSSL_FREE(group,EC_GROUP);
    OSSL_FREE(eph_ec_key, EC_KEY);
    /* Note: free of eph_pub_key already done by free of eph_ec_key */
    OSSL_FREE(bn_x, BN);
    OSSL_FREE(bn_y, BN);
    OSSL_FREE(bctx, BN_CTX);
    return r;
}

/** Encrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in] blk_len Length Block length of AES.
 * @param[in,out] buffer Data to be encrypted. The encrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector. The size is equal to blk_len.
 * @retval TSS2_RC_SUCCESS on success, or TSS2_ESYS_RC_BAD_VALUE and
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters,
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptossl_sym_aes_encrypt(uint8_t * key,
                                TPM2_ALG_ID tpm_sym_alg,
                                TPMI_AES_KEY_BITS key_bits,
                                TPM2_ALG_ID tpm_mode,
                                size_t blk_len,
                                uint8_t * buffer,
                                size_t buffer_size,
                                uint8_t * iv)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    const EVP_CIPHER  *cipher_alg = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int cipher_len;

    if (key == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Bad reference");
    }

    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES input");

    /* Parameter blk_len needed for other crypto libraries */
    (void)blk_len;

    if (key_bits == 128 && tpm_mode == TPM2_ALG_CFB)
        cipher_alg = EVP_aes_128_cfb();
    else if (key_bits == 192 && tpm_mode == TPM2_ALG_CFB)
        cipher_alg = EVP_aes_192_cfb();
    else if (key_bits == 256 && tpm_mode == TPM2_ALG_CFB)
        cipher_alg = EVP_aes_256_cfb();
    else {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE,
                   "AES algorithm not implemented or illegal mode (CFB expected).",
                   cleanup);
    }

    if (tpm_sym_alg != TPM2_ALG_AES) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE,
                   "AES encrypt called with wrong algorithm.", cleanup);
    }

    /* Create and initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Initialize cipher context", cleanup);
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher_alg, get_engine(), key, iv)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Initialize cipher operation", cleanup);
    }
    if (1 != EVP_EncryptInit_ex(ctx, NULL, get_engine(), key, iv)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Set key and iv", cleanup);
    }

    /* Perform the encryption */
    if (1 != EVP_EncryptUpdate(ctx, buffer, &cipher_len, buffer, buffer_size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Encrypt update", cleanup);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, buffer, &cipher_len)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Encrypt final", cleanup);
    }
    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES output");

 cleanup:

    OSSL_FREE(ctx,EVP_CIPHER_CTX);

    return r;
}

/** Decrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in] blk_len Length Block length of AES.
 * @param[in,out] buffer Data to be decrypted. The decrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector. The size is equal to blk_len.
 * @retval TSS2_RC_SUCCESS on success, or TSS2_ESYS_RC_BAD_VALUE and
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters,
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptossl_sym_aes_decrypt(uint8_t * key,
                                TPM2_ALG_ID tpm_sym_alg,
                                TPMI_AES_KEY_BITS key_bits,
                                TPM2_ALG_ID tpm_mode,
                                size_t blk_len,
                                uint8_t * buffer,
                                size_t buffer_size,
                                uint8_t * iv)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    const EVP_CIPHER *cipher_alg = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int cipher_len = 0;

    /* Parameter blk_len needed for other crypto libraries */
    (void)blk_len;

    if (key == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Bad reference");
    }

    if (tpm_sym_alg != TPM2_ALG_AES) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE,
                   "AES encrypt called with wrong algorithm.", cleanup);
    }

    if (key_bits == 128 && tpm_mode == TPM2_ALG_CFB)
        cipher_alg = EVP_aes_128_cfb();
    else if (key_bits == 192 && tpm_mode == TPM2_ALG_CFB)
        cipher_alg = EVP_aes_192_cfb();
    else if (key_bits == 256 && tpm_mode == TPM2_ALG_CFB)
        cipher_alg = EVP_aes_256_cfb();
    else {

        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                   "AES algorithm not implemented.", cleanup);
    }

    /* Create and initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Initialize cipher context", cleanup);
    }

    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES input");

    if (1 != EVP_DecryptInit_ex(ctx, cipher_alg, get_engine(), key, iv)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Initialize cipher operation", cleanup);
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, get_engine(), key, iv)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Set key and iv", cleanup);
    }

    /* Perform the decryption */
    if (1 != EVP_DecryptUpdate(ctx, buffer, &cipher_len, buffer, buffer_size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Encrypt update", cleanup);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, buffer, &cipher_len)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Encrypt final", cleanup);
    }
    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES output");

 cleanup:

    OSSL_FREE(ctx,EVP_CIPHER_CTX);
    return r;
}


/** Initialize OpenSSL crypto backend.
 *
 * Initialize OpenSSL internal tables.
 *
 * @retval TSS2_RC_SUCCESS always returned because OpenSSL_add_all_algorithms
 * does not deliver
 * a return code.
 */
TSS2_RC
iesys_cryptossl_init() {
    ENGINE_load_builtin_engines();
    OpenSSL_add_all_algorithms();
    return TSS2_RC_SUCCESS;
}
