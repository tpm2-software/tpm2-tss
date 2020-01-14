/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>

#include <stdio.h>

#include "tss2_esys.h"

#include "esys_crypto.h"
#include "esys_crypto_mbedtls.h"

#include "esys_iutil.h"
#include "esys_mu.h"
#define LOGMODULE esys_crypto
#include "util/log.h"
#include "util/aux_util.h"

#define HASH (0)
#define HMAC (1)
#define PERSONALIZATION_STRING ("tss2_esys_crypto_mbedtls")

static mbedtls_md_type_t
get_mtls_hash_md(TPM2_ALG_ID hashAlg)
{
    switch (hashAlg) {
        case TPM2_ALG_SHA1:
            return MBEDTLS_MD_SHA1;
            break;
        case TPM2_ALG_SHA256:
            return MBEDTLS_MD_SHA256;
            break;
        case TPM2_ALG_SHA384:
            return MBEDTLS_MD_SHA384;
            break;
        default:
            return MBEDTLS_MD_NONE;
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
iesys_cryptomtls_hash_start(IESYS_CRYPTO_CONTEXT_BLOB ** context,
        TPM2_ALG_ID hashAlg)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    LOG_TRACE("call: context=%p hashAlg=%"PRIu16, context, hashAlg);
    return_if_null(context, "Context is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(context, "Null-Pointer passed for context", TSS2_ESYS_RC_BAD_REFERENCE);
    mbedtls_md_context_t * mycontext = calloc(1, sizeof(mbedtls_md_context_t));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);
    mbedtls_md_init(mycontext);

    mbedtls_md_type_t mdtype = get_mtls_hash_md(hashAlg);
    if (mdtype == MBEDTLS_MD_NONE){
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                "Unsupported hash algorithm (%"PRIu16")", cleanup, hashAlg);
    }

    mbedtls_md_info_t const * mdinfo = mbedtls_md_info_from_type(mdtype);
    if (mdinfo == NULL){
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                "Could not get hash algorithm info", cleanup);
    }

    if (mbedtls_md_setup(mycontext, mdinfo, HASH) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "mbedTLS error", cleanup);
    }

    if (mbedtls_md_starts(mycontext) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "mbedTLS error", cleanup);
    }

    *context = (IESYS_CRYPTO_CONTEXT_BLOB *) mycontext;

    return TSS2_RC_SUCCESS;

cleanup:
    mbedtls_md_free(mycontext);
    free(mycontext);
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
iesys_cryptomtls_hash_update(IESYS_CRYPTO_CONTEXT_BLOB * context,
        const uint8_t * buffer, size_t size)
{
    LOG_TRACE("called for context %p, buffer %p and size %zd", context, buffer,
            size);
    if (context == NULL || buffer == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    mbedtls_md_context_t *mycontext = (mbedtls_md_context_t *) context;
    if (mycontext->hmac_ctx != NULL) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    LOGBLOB_TRACE(buffer, size, "Updating hash with");

    if (mbedtls_md_update(mycontext, buffer, size) != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "mbedTLS hash update");
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
iesys_cryptomtls_hash_update2b(IESYS_CRYPTO_CONTEXT_BLOB * context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    return iesys_cryptomtls_hash_update(context, &b->buffer[0], b->size);
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
iesys_cryptomtls_hash_finish(IESYS_CRYPTO_CONTEXT_BLOB ** context,
        uint8_t * buffer, size_t * size)
{
    LOG_TRACE("called for context-pointer %p, buffer %p and size-pointer %p",
            context, buffer, size);
    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    mbedtls_md_context_t *mycontext = (mbedtls_md_context_t *) *context;
    if (mycontext->hmac_ctx != NULL) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    size_t digest_size = mbedtls_md_get_size(mycontext->md_info);
    if (*size < digest_size) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "Buffer too small");
    }

    if (mbedtls_md_finish(mycontext, buffer) != 0){
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "mbedTLS error.");
    }

    LOGBLOB_TRACE(buffer, digest_size, "read hash result");

    *size = digest_size;
    mbedtls_md_free(mycontext);
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
iesys_cryptomtls_hash_abort(IESYS_CRYPTO_CONTEXT_BLOB ** context)
{
    LOG_TRACE("called for context-pointer %p", context);
    if (context == NULL || *context == NULL) {
        LOG_DEBUG("Null-Pointer passed");
        return;
    }
    mbedtls_md_context_t *mycontext = (mbedtls_md_context_t *) *context;
    if (mycontext->hmac_ctx != NULL) {
        LOG_DEBUG("bad context");
        return;
    }

    mbedtls_md_free(mycontext);
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
iesys_cryptomtls_hmac_start(IESYS_CRYPTO_CONTEXT_BLOB ** context,
        TPM2_ALG_ID hashAlg,
        const uint8_t * key, size_t size)
{
    TSS2_RC r = TSS2_RC_SUCCESS;

    LOG_TRACE("called for context-pointer %p and hmacAlg %d", context, hashAlg);
    LOGBLOB_TRACE(key, size, "Starting  hmac with");
    if (context == NULL || key == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE,
                "Null-Pointer passed in for context");
    }
    mbedtls_md_context_t * mycontext = calloc(1, sizeof(mbedtls_md_context_t));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);
    mbedtls_md_init(mycontext);

    mbedtls_md_type_t mdtype = get_mtls_hash_md(hashAlg);
    if (mdtype == MBEDTLS_MD_NONE){
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                "Unsupported hash algorithm (%"PRIu16")", cleanup, hashAlg);
    }

    mbedtls_md_info_t const * mdinfo = mbedtls_md_info_from_type(mdtype);
    if (mdinfo == NULL){
        goto_error(r, TSS2_ESYS_RC_NOT_IMPLEMENTED,
                "Could not get hash algorithm info", cleanup);
    }

    if (mbedtls_md_setup(mycontext, mdinfo, HMAC) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "mbedTLS error", cleanup);
    }

    if (mbedtls_md_hmac_starts(mycontext, key, size) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "mbedTLS error", cleanup);
    }

    *context = (IESYS_CRYPTO_CONTEXT_BLOB *) mycontext;

    return TSS2_RC_SUCCESS;

cleanup:
    mbedtls_md_free(mycontext);
    free(mycontext);
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
iesys_cryptomtls_hmac_update(IESYS_CRYPTO_CONTEXT_BLOB * context,
        const uint8_t * buffer, size_t size)
{
    LOG_TRACE("called for context %p, buffer %p and size %zd",
            context, buffer, size);
    if (context == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    mbedtls_md_context_t *mycontext = (mbedtls_md_context_t *) context;
    if (mycontext->hmac_ctx == NULL) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    LOGBLOB_TRACE(buffer, size, "Updating hmac with");

    /* Call update with the message */
    if(mbedtls_md_hmac_update(mycontext, buffer, size)) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "mbedTLS HMAC update");
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
iesys_cryptomtls_hmac_update2b(IESYS_CRYPTO_CONTEXT_BLOB * context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    return iesys_cryptomtls_hmac_update(context, &b->buffer[0], b->size);
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
iesys_cryptomtls_hmac_finish(IESYS_CRYPTO_CONTEXT_BLOB ** context,
        uint8_t * buffer, size_t * size)
{

    TSS2_RC r = TSS2_RC_SUCCESS;

    LOG_TRACE("called for context-pointer %p, buffer %p and size-pointer %p",
            context, buffer, size);
    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }

    mbedtls_md_context_t *mycontext = (mbedtls_md_context_t *) *context;
    if (mycontext->hmac_ctx == NULL) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    size_t digest_size = mbedtls_md_get_size(mycontext->md_info);
    if (*size < digest_size) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "Buffer too small");
    }

    if (mbedtls_md_hmac_finish(mycontext, buffer)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "DigestSignFinal", cleanup);
    }

    *size = digest_size;
    LOGBLOB_TRACE(buffer, *size, "read hmac result");

cleanup:
    mbedtls_md_free(mycontext);
    free(mycontext);
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
iesys_cryptomtls_hmac_finish2b(IESYS_CRYPTO_CONTEXT_BLOB ** context, TPM2B * hmac)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, hmac);
    if (context == NULL || *context == NULL || hmac == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    size_t s = hmac->size;
    TSS2_RC ret = iesys_cryptomtls_hmac_finish(context, &hmac->buffer[0], &s);
    hmac->size = s;
    return ret;
}

/** Release the resources of an HAMC object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the HMAC object.
 */
    void
iesys_cryptomtls_hmac_abort(IESYS_CRYPTO_CONTEXT_BLOB ** context)
{
    LOG_TRACE("called for context-pointer %p", context);
    if (context == NULL || *context == NULL) {
        LOG_DEBUG("Null-Pointer passed");
        return;
    }

    mbedtls_md_context_t *mycontext = (mbedtls_md_context_t *) *context;
    if (mycontext->hmac_ctx == NULL) {
        LOG_DEBUG("bad context");
        return;
    }

    mbedtls_md_free(mycontext);
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
iesys_cryptomtls_random2b(TPM2B_NONCE * nonce, size_t num_bytes)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    char *personalization = PERSONALIZATION_STRING;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg , mbedtls_entropy_func, &entropy,
                (const unsigned char *) personalization,
                strlen(personalization)) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Failure in random number generator.", cleanup);
    }

    if (num_bytes == 0) {
        nonce->size = sizeof(TPMU_HA);
    } else {
        nonce->size = num_bytes;
    }

    if (mbedtls_ctr_drbg_random(&ctr_drbg, nonce->buffer, nonce->size) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Failure in random number generator.", cleanup);
    }
cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return r;
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
iesys_cryptomtls_pk_encrypt(TPM2B_PUBLIC * pub_tpm_key,
        size_t in_size,
        BYTE * in_buffer,
        size_t max_out_size,
        BYTE * out_buffer,
        size_t * out_size, const char *label)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    mbedtls_rsa_context rsa_key;
    mbedtls_mpi bne, bnn;
    int padding;
    char *label_copy = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    char *personalization = PERSONALIZATION_STRING;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg , mbedtls_entropy_func, &entropy,
                (const unsigned char *) personalization,
                strlen(personalization)) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Failure in random number generator.", cleanup);
    }

    mbedtls_md_type_t hashAlg = get_mtls_hash_md(pub_tpm_key->publicArea.nameAlg);
    if (hashAlg == MBEDTLS_MD_NONE) {
        LOG_ERROR("Unsupported hash algorithm (%"PRIu16")",
                pub_tpm_key->publicArea.nameAlg);
        return TSS2_ESYS_RC_NOT_IMPLEMENTED;
    }

    mbedtls_mpi_init(&bne);
    mbedtls_mpi_init(&bnn);

    switch (pub_tpm_key->publicArea.parameters.rsaDetail.scheme.scheme) {
        case TPM2_ALG_RSAES:
            padding = MBEDTLS_RSA_PKCS_V15;
            break;
        case TPM2_ALG_OAEP:
            padding = MBEDTLS_RSA_PKCS_V21;
            break;
        default:
            goto_error(r, TSS2_ESYS_RC_BAD_VALUE, "Illegal RSA scheme", cleanup);
    }

    mbedtls_rsa_init(&rsa_key, padding, hashAlg);

    UINT32 exp;
    if (pub_tpm_key->publicArea.parameters.rsaDetail.exponent == 0)
        exp = 65537;
    else
        exp = pub_tpm_key->publicArea.parameters.rsaDetail.exponent;
    if (mbedtls_mpi_lset(&bne, exp) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Could not set exponent.", cleanup_with_rsa);
    }

    if (mbedtls_mpi_read_binary(&bnn, pub_tpm_key->publicArea.unique.rsa.buffer,
                pub_tpm_key->publicArea.unique.rsa.size) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Could not set modulus.", cleanup_with_rsa);
    }

    if (mbedtls_rsa_import(&rsa_key, &bnn, NULL, NULL, NULL, &bne) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Could not import N and e.", cleanup_with_rsa);
    }

    if (mbedtls_rsa_complete(&rsa_key) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Could not complete creation of the RSA key.", cleanup_with_rsa);
    }

    if (rsa_key.len > max_out_size){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Encrypted data too big", cleanup_with_rsa);
    }
    *out_size = rsa_key.len;

    if (padding == MBEDTLS_RSA_PKCS_V15){
        if (mbedtls_rsa_rsaes_pkcs1_v15_encrypt(&rsa_key, mbedtls_ctr_drbg_random,
                    &ctr_drbg, MBEDTLS_RSA_PUBLIC, in_size, in_buffer, out_buffer) != 0){
            goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                    "Could not encrypt data.", cleanup_with_rsa);
        }
    } else if (padding == MBEDTLS_RSA_PKCS_V21){
        label_copy = strdup(label);
        if (label_copy == NULL){
            goto_error(r, TSS2_ESYS_RC_MEMORY,
                    "Could not duplicate OAEP label", cleanup_with_rsa);
        }

        size_t label_size = strlen(label_copy) + 1;
        if (mbedtls_rsa_rsaes_oaep_encrypt(&rsa_key, mbedtls_ctr_drbg_random,
                    &ctr_drbg, MBEDTLS_RSA_PUBLIC, (unsigned char *)label_copy,
                    label_size, in_size, in_buffer, out_buffer) != 0){
            goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                    "Could not encrypt data.", cleanup_with_rsa);
        }
    } else {
        goto_error(r, TSS2_ESYS_RC_MEMORY,
                "Invalid padding mode.", cleanup_with_rsa);
    }

    *out_size = rsa_key.len;

cleanup_with_rsa:
    mbedtls_rsa_free(&rsa_key);

cleanup:
    mbedtls_mpi_free(&bne);
    mbedtls_mpi_free(&bnn);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if(label_copy) {
        free(label_copy);
    }
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
iesys_cryptomtls_get_ecdh_point(TPM2B_PUBLIC *key,
        size_t max_out_size,
        TPM2B_ECC_PARAMETER *Z,
        TPMS_ECC_POINT *Q,
        BYTE * out_buffer,
        size_t * out_size)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point Q_mbedtls;
    mbedtls_ecp_point_init(&Q_mbedtls);
    mbedtls_ecp_point Qp_mbedtls;
    mbedtls_ecp_point_init(&Qp_mbedtls);
    mbedtls_mpi d_mbedtls, z_mbedtls;
    mbedtls_mpi_init(&d_mbedtls);
    mbedtls_mpi_init(&z_mbedtls);
    mbedtls_ecp_group_id curveId = MBEDTLS_ECP_DP_NONE;

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    char *personalization = PERSONALIZATION_STRING;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg , mbedtls_entropy_func, &entropy,
                (const unsigned char *) personalization,
                strlen(personalization)) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Failure in random number generator.", cleanup);
    }

    /* Set ossl constant for curve type and create group for curve */
    uint16_t parameter_size = 0;
    switch (key->publicArea.parameters.eccDetail.curveID) {
        case TPM2_ECC_NIST_P192:
            curveId = MBEDTLS_ECP_DP_SECP192R1;
            parameter_size = 24;
            break;
        case TPM2_ECC_NIST_P224:
            curveId = MBEDTLS_ECP_DP_SECP224R1;
            parameter_size = 28;
            break;
        case TPM2_ECC_NIST_P256:
            curveId = MBEDTLS_ECP_DP_SECP256R1;
            parameter_size = 32;
            break;
        case TPM2_ECC_NIST_P384:
            curveId = MBEDTLS_ECP_DP_SECP384R1;
            parameter_size = 48;
            break;
        case TPM2_ECC_NIST_P521:
            curveId = MBEDTLS_ECP_DP_SECP521R1;
            parameter_size = 66;
            break;
        default:
            return_error(TSS2_ESYS_RC_NOT_IMPLEMENTED,
                    "ECC curve not implemented.");
    }

    if (mbedtls_ecp_group_load(&group, curveId) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Create group for curve", cleanup);
    }

    /* Generate ephemeral public key and write it to TSS types */
    if (mbedtls_ecdh_gen_public(&group, &d_mbedtls, &Q_mbedtls,
                mbedtls_ctr_drbg_random,
                &ctr_drbg) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Generate public key for ECDH", cleanup);
    }

    if (mbedtls_mpi_write_binary(&Q_mbedtls.X, Q->x.buffer,
                parameter_size) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Converting point X to TSS type", cleanup);
    }
    Q->x.size = parameter_size;

    if (mbedtls_mpi_write_binary(&Q_mbedtls.Y,Q->y.buffer,
                parameter_size) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Converting point Y to TSS type", cleanup);
    }
    Q->y.size = parameter_size;

    /* Convert the TPM key into an mbedTLS key */
    if (mbedtls_mpi_read_binary(&Qp_mbedtls.X, key->publicArea.unique.ecc.x.buffer,
                key->publicArea.unique.ecc.x.size) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Converting X of TPM key", cleanup);
    }
    if (mbedtls_mpi_read_binary(&Qp_mbedtls.Y, key->publicArea.unique.ecc.y.buffer,
                key->publicArea.unique.ecc.y.size) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Converting Y of TPM key", cleanup);
    }
    unsigned char z_buf[1] = {1};
    if (mbedtls_mpi_read_binary(&Qp_mbedtls.Z, z_buf, 1)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Converting X of TPM key", cleanup);
    }

    if (mbedtls_ecp_check_pubkey(&group, &Qp_mbedtls) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "TPM key is invalid", cleanup);
    }


    /* Doing the key exchange */
    if (mbedtls_ecdh_compute_shared(&group, &z_mbedtls,
                &Qp_mbedtls, &d_mbedtls,
                mbedtls_ctr_drbg_random,
                &ctr_drbg) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Computing the shared secret for ECDH", cleanup);
    }

    /* Export the z-value */
    if (mbedtls_mpi_write_binary(&z_mbedtls, Z->buffer,
                parameter_size) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Converting the shared secret into a TSS type", cleanup);
    }
    Z->size = parameter_size;;
    size_t offset = 0;
    r = Tss2_MU_TPMS_ECC_POINT_Marshal(Q,  out_buffer, max_out_size,
            &offset);
    goto_if_error(r, "Error marshaling", cleanup);
    *out_size = offset;
cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecp_point_free(&Q_mbedtls);
    mbedtls_ecp_point_free(&Qp_mbedtls);
    mbedtls_mpi_free(&d_mbedtls);
    mbedtls_mpi_free(&z_mbedtls);
    mbedtls_ecp_group_free(&group);
    return r;

}

static TSS2_RC iesys_cryptomtls_sym_aes_crypt(uint8_t * key,
        TPM2_ALG_ID tpm_sym_alg,
        TPMI_AES_KEY_BITS key_bits,
        TPM2_ALG_ID tpm_mode,
        size_t blk_len,
        uint8_t * buffer,
        size_t buffer_size,
        uint8_t * iv,
        uint8_t encrypt){
    TSS2_RC r = TSS2_RC_SUCCESS;
    uint8_t * out_buffer = NULL;

    if (key == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Bad reference");
    }

    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES input");

    /* Parameter blk_len needed for other crypto libraries */
    (void)blk_len;

    if (tpm_sym_alg != TPM2_ALG_AES) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE,
                "AES encrypt called with wrong algorithm.", cleanup);
    }

    if (tpm_mode != TPM2_ALG_CFB){
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE,
                "Illegal mode (CFB expected)", cleanup);
    }

    if (key_bits != 128 && key_bits != 192 && key_bits != 256){
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE,
                "Illegal key size", cleanup);
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    /*
     * This is dependent on the encryption mode. If the TSS ever
     * supports anything but CFB, mbedtls_aes_setkey_dec might be
     * necessary.
     */
    if (mbedtls_aes_setkey_enc(&aes, key, key_bits) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Could not set AES key in mbedTLS", cleanup);
    }

    size_t offset = 0;
    out_buffer = calloc(buffer_size, 1);
    if (out_buffer == NULL){
        goto_error(r, TSS2_ESYS_RC_MEMORY,
                "Could not allocate memory for AES encryption", cleanup);
    }
    if (mbedtls_aes_crypt_cfb128(&aes, encrypt, buffer_size,
                &offset, iv, buffer, out_buffer) != 0){
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                "Could not execute AES crypto operation", cleanup);
    }
    memcpy(buffer, out_buffer, buffer_size);

    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES output");

cleanup:
    mbedtls_aes_free(&aes);
    free(out_buffer);
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
iesys_cryptomtls_sym_aes_encrypt(uint8_t * key,
        TPM2_ALG_ID tpm_sym_alg,
        TPMI_AES_KEY_BITS key_bits,
        TPM2_ALG_ID tpm_mode,
        size_t blk_len,
        uint8_t * buffer,
        size_t buffer_size,
        uint8_t * iv)
{
    return iesys_cryptomtls_sym_aes_crypt(key, tpm_sym_alg, key_bits,
            tpm_mode, blk_len, buffer, buffer_size, iv, MBEDTLS_AES_ENCRYPT);
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
iesys_cryptomtls_sym_aes_decrypt(uint8_t * key,
        TPM2_ALG_ID tpm_sym_alg,
        TPMI_AES_KEY_BITS key_bits,
        TPM2_ALG_ID tpm_mode,
        size_t blk_len,
        uint8_t * buffer,
        size_t buffer_size,
        uint8_t * iv)
{
    return iesys_cryptomtls_sym_aes_crypt(key, tpm_sym_alg, key_bits,
            tpm_mode, blk_len, buffer, buffer_size, iv, MBEDTLS_AES_DECRYPT);
}


/** Should initialize the mbedTLS backend but since there is not much to
 * initialize, just returns \ref TSS2_RC_SUCCESS.
 * @retval TSS2_RC_SUCCESS
 */
TSS2_RC
iesys_cryptomtls_init() {
    return TSS2_RC_SUCCESS;
}

