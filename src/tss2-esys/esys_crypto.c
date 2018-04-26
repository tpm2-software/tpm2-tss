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

#define _GNU_SOURCE

#include <gcrypt.h>
#include <stdio.h>

#include "tss2_esys.h"

#include "esys_crypto.h"
#include "esys_iutil.h"
#include "esys_mu.h"
#define LOGMODULE esys
#include "util/log.h"

/** Context to hold temporary values for iesys_crypto */
typedef struct _IESYS_CRYPTO_CONTEXT {
    enum {
        IESYS_CRYPTOGCRY_TYPE_HASH = 1,
        IESYS_CRYPTOGCRY_TYPE_HMAC,
    } type; /**< The type of context to hold; hash or hmac */
    union {
        struct {
            gcry_md_hd_t gcry_context;
            int gcry_hash_alg;
            size_t hash_len;
        } hash; /**< the state variables for a hash context */
        struct {
            gcry_mac_hd_t gcry_context;
            int gcry_hmac_alg;
            size_t hmac_len;
        } hmac; /**< the state variables for an hmac context */
    };
} IESYS_CRYPTOGCRY_CONTEXT;

/** Provide the digest size for a given hash algorithm.
 *
 * This function provides the size of the digest for a given hash algorithm.
 *
 * @param[in] hashAlg The hash algorithm to get the size for.
 * @param[out] size The side of a digest of the hash algorithm.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE if hashAlg is unknown or unsupported.
 */
TSS2_RC
iesys_crypto_hash_get_digest_size(TPM2_ALG_ID hashAlg, size_t * size)
{
    LOG_TRACE("call: hashAlg=%"PRIu16" size=%p", hashAlg, size);
    if (size == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    switch (hashAlg) {
    case TPM2_ALG_SHA1:
        *size = TPM2_SHA1_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA256:
        *size = TPM2_SHA256_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA384:
        *size = TPM2_SHA384_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA512:
        *size = TPM2_SHA512_DIGEST_SIZE;
        break;
    case TPM2_ALG_SM3_256:
        *size = TPM2_SM3_256_DIGEST_SIZE;
        break;
    default:
        LOG_ERROR("Unsupported hash algorithm (%"PRIu16")", hashAlg);
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    LOG_TRACE("return: *size=%zu", *size);
    return TSS2_RC_SUCCESS;
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
iesys_cryptogcry_hash_start(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                            TPM2_ALG_ID hashAlg)
{
    LOG_TRACE("call: context=%p hashAlg=%"PRIu16, context, hashAlg);
    return_if_null(context, "Context is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    IESYS_CRYPTOGCRY_CONTEXT *mycontext;
    mycontext = calloc(1, sizeof(IESYS_CRYPTOGCRY_CONTEXT));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);
    mycontext->type = IESYS_CRYPTOGCRY_TYPE_HASH;

    switch (hashAlg) {
    case TPM2_ALG_SHA1:
        mycontext->hash.gcry_hash_alg = GCRY_MD_SHA1;
        break;
    case TPM2_ALG_SHA256:
        mycontext->hash.gcry_hash_alg = GCRY_MD_SHA256;
        break;
    case TPM2_ALG_SHA384:
        mycontext->hash.gcry_hash_alg = GCRY_MD_SHA384;
        break;
    default:
        LOG_ERROR("Unsupported hash algorithm (%"PRIu16")", hashAlg);
        free(mycontext);
        return TSS2_ESYS_RC_NOT_IMPLEMENTED;
    }
    int hash_len = gcry_md_get_algo_dlen(mycontext->hash.gcry_hash_alg);
    if (hash_len <= 0) {
        LOG_ERROR("Unsupported hash algorithm (%"PRIu16")", hashAlg);
        free(mycontext);
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    mycontext->hash.hash_len = hash_len;

    gcry_error_t r = gcry_md_open(&mycontext->hash.gcry_context,
                                  mycontext->hash.gcry_hash_alg, 0);
    if (r != 0) {
        LOG_ERROR("GCry error.");
        free(mycontext);
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }

    if (context == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    *context = (IESYS_CRYPTO_CONTEXT_BLOB *) mycontext;

    return TSS2_RC_SUCCESS;
}

/** Update the digest value of a digest object from a byte buffer.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm of the context.
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] buffer The data for the update.
 * @param[in] size The size of the data buffer.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 */
TSS2_RC
iesys_cryptogcry_hash_update(IESYS_CRYPTO_CONTEXT_BLOB * context,
                             const uint8_t * buffer, size_t size)
{
    LOG_TRACE("called for context %p, buffer %p and size %zd", context, buffer,
              size);
    if (context == NULL || buffer == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext = (IESYS_CRYPTOGCRY_CONTEXT *) context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HASH) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    LOGBLOB_TRACE(buffer, size, "Updating hash with");

    gcry_md_write(mycontext->hash.gcry_context, buffer, size);

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
iesys_cryptogcry_hash_update2b(IESYS_CRYPTO_CONTEXT_BLOB * context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret = iesys_cryptogcry_hash_update(context, &b->buffer[0], b->size);
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
iesys_cryptogcry_hash_finish(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                             uint8_t * buffer, size_t * size)
{
    LOG_TRACE("called for context-pointer %p, buffer %p and size-pointer %p",
              context, buffer, size);
    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext = * context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HASH) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    if (*size < mycontext->hash.hash_len) {
        LOG_ERROR("Buffer too small");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    uint8_t *cpHash = gcry_md_read(mycontext->hash.gcry_context,
                                   mycontext->hash.gcry_hash_alg);
    if (cpHash == NULL) {
        LOG_ERROR("GCry error.");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }

    LOGBLOB_TRACE(cpHash, mycontext->hash.hash_len, "read hash result");

    *size = mycontext->hash.hash_len;
    memmove(buffer, cpHash, *size);

    gcry_md_close(mycontext->hash.gcry_context);

    free(mycontext);
    *context = NULL;

    return TSS2_RC_SUCCESS;
}

/** Get the digest value of a digest object and close the context.
 *
 * The digest value will written to a passed TPM2B object and the
 * digest object are released.
 * @param[in,out] context The context of the digest object to be released
 * @param[out] b The TPM2B object for the digest (caller-allocated).
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptogcry_hash_finish2b(IESYS_CRYPTO_CONTEXT_BLOB ** context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || *context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    size_t s = b->size;
    TSS2_RC ret = iesys_cryptogcry_hash_finish(context, &b->buffer[0], &s);
    b->size = s;
    return ret;
}

/** Release the resources of a digest object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the digest object.
 */
void
iesys_cryptogcry_hash_abort(IESYS_CRYPTO_CONTEXT_BLOB ** context)
{
    LOG_TRACE("called for context-pointer %p", context);
    if (context == NULL || *context == NULL) {
        LOG_DEBUG("Null-Pointer passed");
        return;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext =
        (IESYS_CRYPTOGCRY_CONTEXT *) * context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HASH) {
        LOG_DEBUG("bad context");
        return;
    }

    gcry_md_close(mycontext->hash.gcry_context);
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
iesys_cryptogcry_hmac_start(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                            TPM2_ALG_ID hmacAlg,
                            const uint8_t * key, size_t size)
{
    TSS2_RC r;

    LOG_TRACE("called for context-pointer %p and hmacAlg %d", context, hmacAlg);
    LOGBLOB_TRACE(key, size, "Starting  hmac with");
    if (context == NULL || key == NULL) {
        LOG_ERROR("Null-Pointer passed in for context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext =
        calloc(1, sizeof(IESYS_CRYPTOGCRY_CONTEXT));
    if (mycontext == NULL) {
        LOG_ERROR("Out of Memory");
        return TSS2_ESYS_RC_MEMORY;
    }

    switch (hmacAlg) {
    case TPM2_ALG_SHA1:
        mycontext->hmac.gcry_hmac_alg = GCRY_MAC_HMAC_SHA1;
        break;
    case TPM2_ALG_SHA256:
        mycontext->hmac.gcry_hmac_alg = GCRY_MAC_HMAC_SHA256;
        break;
    default:
        LOG_ERROR("Unsupported hmac algo.");
        free(mycontext);
        return TSS2_ESYS_RC_NOT_IMPLEMENTED;
    }

    int hmac_len = gcry_mac_get_algo_maclen(mycontext->hmac.gcry_hmac_alg);
    if (hmac_len <= 0) {
        LOG_ERROR("GCry error.");
        free(mycontext);
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }

    mycontext->type = IESYS_CRYPTOGCRY_TYPE_HMAC;
    mycontext->hmac.hmac_len = hmac_len;

    r = gcry_mac_open(&mycontext->hmac.gcry_context,
                      mycontext->hmac.gcry_hmac_alg, 0, NULL);
    if (r != 0) {
        LOG_ERROR("GCry error.");
        free(mycontext);
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }

    r = gcry_mac_setkey(mycontext->hmac.gcry_context, key, size);
    if (r != 0) {
        LOG_ERROR("GCry error.");
        gcry_mac_close(mycontext->hmac.gcry_context);
        free(mycontext);
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }

    *context = (IESYS_CRYPTO_CONTEXT_BLOB *) mycontext;

    return TSS2_RC_SUCCESS;
}

/** Provide the context an HMAC digest object from a byte TPM2B key.
 *
 * The context will be created and initialized according to the hash function
 * and the used HMAC key.
 * @param[out] context The created context.
 * @param[in] hmacAlg The hash algorithm for the HMAC computation.
 * @param[in] key The TPM2B object of the HMAC key.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_ESYS_RC_MEMORY Memory cannot be allocated.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto library.
 */
TSS2_RC
iesys_cryptogcry_hmac_start2b(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                              TPM2_ALG_ID hmacAlg, TPM2B * key)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, key);
    if (context == NULL || key == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret = iesys_cryptogcry_hmac_start(context, hmacAlg, &key->buffer[0],
                                              key->size);
    return ret;
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
iesys_cryptogcry_hmac_update(IESYS_CRYPTO_CONTEXT_BLOB * context,
                             const uint8_t * buffer, size_t size)
{
    LOG_TRACE("called for context %p, buffer %p and size %zd",
              context, buffer, size);
    if (context == NULL || buffer == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext = (IESYS_CRYPTOGCRY_CONTEXT *) context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HMAC) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    LOGBLOB_TRACE(buffer, size, "Updating hmac with");

    gcry_mac_write(mycontext->hmac.gcry_context, buffer, size);

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
iesys_cryptogcry_hmac_update2b(IESYS_CRYPTO_CONTEXT_BLOB * context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret = iesys_cryptogcry_hmac_update(context, &b->buffer[0], b->size);
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
iesys_cryptogcry_hmac_finish(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                             uint8_t * buffer, size_t * size)
{
    LOG_TRACE("called for context-pointer %p, buffer %p and size-pointer %p",
              context, buffer, size);
    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext =
        (IESYS_CRYPTOGCRY_CONTEXT *) * context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HMAC) {
        LOG_ERROR("bad context");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    if (*size < mycontext->hmac.hmac_len) {
        LOG_ERROR("Buffer too small");
        return TSS2_ESYS_RC_BAD_SIZE;
    }

    TSS2_RC r = gcry_mac_read(mycontext->hmac.gcry_context, buffer, size);
    if (r != 0) {
        LOG_ERROR("GCry error.");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }

    LOGBLOB_TRACE(buffer, *size, "read hmac result");

    gcry_mac_close(mycontext->hmac.gcry_context);

    free(mycontext);
    *context = NULL;

    return TSS2_RC_SUCCESS;
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
iesys_cryptogcry_hmac_finish2b(IESYS_CRYPTO_CONTEXT_BLOB ** context, TPM2B * hmac)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, hmac);
    if (context == NULL || *context == NULL || hmac == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    size_t s = hmac->size;
    TSS2_RC ret = iesys_cryptogcry_hmac_finish(context, &hmac->buffer[0], &s);
    hmac->size = s;
    return ret;
}

/** Release the resources of an HAMC object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the HMAC object.
 */
void
iesys_cryptogcry_hmac_abort(IESYS_CRYPTO_CONTEXT_BLOB ** context)
{
    LOG_TRACE("called for context-pointer %p", context);
    if (context == NULL || *context == NULL) {
        LOG_DEBUG("Null-Pointer passed");
        return;
    }
    if (*context != NULL) {
        IESYS_CRYPTOGCRY_CONTEXT *mycontext =
            (IESYS_CRYPTOGCRY_CONTEXT *) * context;
        if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HMAC) {
            LOG_DEBUG("bad context");
            return;
        }

        gcry_mac_close(mycontext->hmac.gcry_context);

        free(mycontext);
        *context = NULL;
    }
}

/** Compute the command or response parameter hash.
 *
 * These hashes are needed for the computation of the HMAC used for the
 * authorization of commands, or for the HMAC used for checking the responses.
 * The name parameters are only used for the command parameter hash (cp) and
 * must be NULL for the computation of the response parameter rp hash (rp).
 * @param[in] alg The hash algorithm.
 * @param[in] rcBuffer The response code in marshaled form.
 * @param[in] ccBuffer The command code in marshaled form.
 * @param[in] name1, name2, name3 The names associated with the corresponding
 *            handle. Must be NULL if no handle is passed.
 * @param[in] pBuffer The byte buffer or the command or the response.
 * @param[in] pBuffer_size The size of the command or response.
 * @param[out] pHash The result digest.
 * @param[out] pHash_size The size of the result digest.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 */

TSS2_RC
iesys_crypto_pHash(TPM2_ALG_ID alg,
                   const uint8_t rcBuffer[4],
                   const uint8_t ccBuffer[4],
                   const TPM2B_NAME * name1,
                   const TPM2B_NAME * name2,
                   const TPM2B_NAME * name3,
                   const uint8_t * pBuffer,
                   size_t pBuffer_size, uint8_t * pHash, size_t * pHash_size)
{
    LOG_TRACE("called");
    if (ccBuffer == NULL || pBuffer == NULL || pHash == NULL
        || pHash_size == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    IESYS_CRYPTO_CONTEXT_BLOB *cryptoContext;

    TSS2_RC r = iesys_crypto_hash_start(&cryptoContext, alg);
    return_if_error(r, "Error");

    if (rcBuffer != NULL) {
        r = iesys_crypto_hash_update(cryptoContext, &rcBuffer[0], 4);
        goto_if_error(r, "Error", error);
    }

    r = iesys_crypto_hash_update(cryptoContext, &ccBuffer[0], 4);
    goto_if_error(r, "Error", error);

    if (name1 != NULL) {
        r = iesys_crypto_hash_update2b(cryptoContext, (TPM2B *) name1);
        goto_if_error(r, "Error", error);
    }

    if (name2 != NULL) {
        r = iesys_crypto_hash_update2b(cryptoContext, (TPM2B *) name2);
        goto_if_error(r, "Error", error);
    }

    if (name3 != NULL) {
        r = iesys_crypto_hash_update2b(cryptoContext, (TPM2B *) name3);
        goto_if_error(r, "Error", error);
    }

    r = iesys_crypto_hash_update(cryptoContext, pBuffer, pBuffer_size);
    goto_if_error(r, "Error", error);

    r = iesys_crypto_hash_finish(&cryptoContext, pHash, pHash_size);
    goto_if_error(r, "Error", error);

    return r;

 error:
    iesys_crypto_hash_abort(&cryptoContext);
    return r;
}

/** Compute the HMAC for authorization.
 *
 * Based on the session nonces, caller nonce, TPM nonce, if used encryption and
 * decryption nonce, the command parameter hash, and the session attributes the
 * HMAC used for authorization is computed.
 * @param[in] alg The hash algorithm used for HMAC computation.
 * @param[in] hmacKey The HMAC key byte buffer.
 * @param[in] hmacKeySize The size of the HMAC key byte buffer.
 * @param[in] pHash The command parameter hash byte buffer.
 * @param[in] pHash_size The size of the command parameter hash byte buffer.
 * @param[in] nonceNewer The TPM nonce.
 * @param[in] nonceOlder The caller nonce.
 * @param[in] nonceDecrypt The decrypt nonce (NULL if not used).
 * @param[in] nonceEncrypt The encrypt nonce (NULL if not used).
 * @param[in] sessionAttributes The attributes used for the current
 *            authentication.
 * @param[out] hmac The computed HMAC.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_ESYS_RC_BAD_REFERENCE If a pointer is invalid.
 */
TSS2_RC
iesys_crypto_authHmac(TPM2_ALG_ID alg,
                      uint8_t * hmacKey, size_t hmacKeySize,
                      const uint8_t * pHash,
                      size_t pHash_size,
                      const TPM2B_NONCE * nonceNewer,
                      const TPM2B_NONCE * nonceOlder,
                      const TPM2B_NONCE * nonceDecrypt,
                      const TPM2B_NONCE * nonceEncrypt,
                      TPMA_SESSION sessionAttributes, TPM2B_AUTH * hmac)
{
    LOG_TRACE("called");
    if (hmacKey == NULL || pHash == NULL || nonceNewer == NULL ||
        nonceOlder == NULL || hmac == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    uint8_t sessionAttribs[sizeof(sessionAttributes)];
    size_t sessionAttribs_size = 0;

    IESYS_CRYPTO_CONTEXT_BLOB *cryptoContext;

    TSS2_RC r =
        iesys_crypto_hmac_start(&cryptoContext, alg, hmacKey, hmacKeySize);
    return_if_error(r, "Error");

    r = iesys_crypto_hmac_update(cryptoContext, pHash, pHash_size);
    goto_if_error(r, "Error", error);

    r = iesys_crypto_hmac_update2b(cryptoContext, (TPM2B *) nonceNewer);
    goto_if_error(r, "Error", error);

    r = iesys_crypto_hmac_update2b(cryptoContext, (TPM2B *) nonceOlder);
    goto_if_error(r, "Error", error);

    if (nonceDecrypt != NULL) {
        r = iesys_crypto_hmac_update2b(cryptoContext, (TPM2B *) nonceDecrypt);
        goto_if_error(r, "Error", error);
    }

    if (nonceEncrypt != NULL) {
        r = iesys_crypto_hmac_update2b(cryptoContext, (TPM2B *) nonceEncrypt);
        goto_if_error(r, "Error", error);
    }

    r = Tss2_MU_TPMA_SESSION_Marshal(sessionAttributes,
                                     &sessionAttribs[0],
                                     sizeof(sessionAttribs),
                                     &sessionAttribs_size);
    goto_if_error(r, "Error", error);

    r = iesys_crypto_hmac_update(cryptoContext, &sessionAttribs[0],
                                 sessionAttribs_size);
    goto_if_error(r, "Error", error);

    r = iesys_crypto_hmac_finish2b(&cryptoContext, (TPM2B *) hmac);
    goto_if_error(r, "Error", error);

    return r;

 error:
    iesys_crypto_hmac_abort(&cryptoContext);
    return r;

}

/**
 * HMAC computation for inner loop of KDFa key derivation.
 *
 * Except of ECDH this function is used for key derivation.
 * @param[in] alg The algorithm used for the HMAC.
 * @param[in] hmacKey The hmacKey used in KDFa.
 * @param[in] hmacKeySize The size of the HMAC key.
 * @param[in] counter The curren iteration step.
 * @param[in] label Indicates the use of the produced key.
 * @param[in] contextU, contextV are used for construction of a binary string
 *            containing information related to the derived key.
 * @param[in] bitlength The size of the generated key in bits.
 * @param[out] hmac Byte buffer for the generated HMAC key (caller-allocated).
 * @param[out] hmacSize  Size of the generated HMAC key.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 */
TSS2_RC
iesys_crypto_KDFaHmac(TPM2_ALG_ID alg,
                      uint8_t * hmacKey,
                      size_t hmacKeySize,
                      uint32_t counter,
                      const char *label,
                      TPM2B_NONCE * contextU,
                      TPM2B_NONCE * contextV,
                      uint32_t bitlength, uint8_t * hmac, size_t * hmacSize)
{
    LOG_TRACE("called");
    if (hmacKey == NULL || contextU == NULL || contextV == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    uint8_t buffer32[sizeof(uint32_t)];
    size_t buffer32_size = 0;

    IESYS_CRYPTO_CONTEXT_BLOB *cryptoContext;

    TSS2_RC r =
        iesys_crypto_hmac_start(&cryptoContext, alg, hmacKey, hmacKeySize);
    return_if_error(r, "Error");

    r = Tss2_MU_UINT32_Marshal(counter, &buffer32[0], sizeof(UINT32),
                               &buffer32_size);
    goto_if_error(r, "Marsahling", error);
    r = iesys_crypto_hmac_update(cryptoContext, &buffer32[0], buffer32_size);
    goto_if_error(r, "HMAC-Update", error);

    if (label != NULL) {
        size_t lsize = strlen(label) + 1;
        r = iesys_crypto_hmac_update(cryptoContext, (uint8_t *) label, lsize);
        goto_if_error(r, "Error", error);
    }

    r = iesys_crypto_hmac_update2b(cryptoContext, (TPM2B *) contextU);
    goto_if_error(r, "Error", error);

    r = iesys_crypto_hmac_update2b(cryptoContext, (TPM2B *) contextV);
    goto_if_error(r, "Error", error);

    buffer32_size = 0;
    r = Tss2_MU_UINT32_Marshal(bitlength, &buffer32[0], sizeof(UINT32),
                               &buffer32_size);
    goto_if_error(r, "Marsahling", error);
    r = iesys_crypto_hmac_update(cryptoContext, &buffer32[0], buffer32_size);
    goto_if_error(r, "Error", error);

    r = iesys_crypto_hmac_finish(&cryptoContext, hmac, hmacSize);
    goto_if_error(r, "Error", error);

    return r;

 error:
    iesys_crypto_hmac_abort(&cryptoContext);
    return r;
}

/**
 * KDFa Key derivation.
 *
 * Except of ECDH this function is used for key derivation.
 * @param[in] hashAlg The hash algorithm to use.
 * @param[in] hmacKey The hmacKey used in KDFa.
 * @param[in] hmacKeySize The size of the HMAC key.
 * @param[in] label Indicates the use of the produced key.
 * @param[in] contextU, contextV are used for construction of a binary string
 *            containing information related to the derived key.
 * @param[in] bitLength The size of generated key in bits.
 * @param[in,out] counterInOut Counter for the KDFa iterations. If set, the
 *                value will be used for the firt iteration step. The final
 *                counter value will be written to  counterInOut.
 * @param[out] outKey Byte buffer for the derived key (caller-allocated).
 * @param[in] use_digest_size Indicate whether the digest size of hashAlg is
 *            used as size of the generated key or the bitLength parameter is
 *            used.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_VALUE if hashAlg is unknown or unsupported.
 */
TSS2_RC
iesys_crypto_KDFa(TPM2_ALG_ID hashAlg,
                  uint8_t * hmacKey,
                  size_t hmacKeySize,
                  const char *label,
                  TPM2B_NONCE * contextU,
                  TPM2B_NONCE * contextV,
                  uint32_t bitLength,
                  uint32_t * counterInOut,
                  BYTE * outKey,
                  BOOL use_digest_size)
{
    LOG_DEBUG("IESYS KDFa hmac key hashAlg: %i label: %s bitLength: %i",
              hashAlg, label, bitLength);
    if (counterInOut != NULL)
        LOG_TRACE("IESYS KDFa hmac key counterInOut: %i", *counterInOut);
    LOGBLOB_DEBUG(hmacKey, hmacKeySize, "IESYS KDFa hmac key");

    LOGBLOB_DEBUG(&contextU->buffer[0], contextU->size,
                  "IESYS KDFa contextU key");
    LOGBLOB_DEBUG(&contextV->buffer[0], contextV->size,
                  "IESYS KDFa contextV key");
    BYTE *subKey = outKey;
    UINT32 counter = 0;
    INT32 bytes = 0;
    size_t hlen = 0;
    TSS2_RC r = iesys_crypto_hash_get_digest_size(hashAlg, &hlen);
    return_if_error(r, "Error");
    if (counterInOut != NULL)
        counter = *counterInOut;
    bytes = use_digest_size ? hlen : (bitLength + 7) / 8;
    LOG_DEBUG("IESYS KDFa hmac key bytes: %i", bytes);

     /* Fill outKey with results from KDFaHmac */
    for (; bytes > 0; subKey = &subKey[hlen], bytes = bytes - hlen) {
        LOG_TRACE("IESYS KDFa hmac key bytes: %i", bytes);
        //if(bytes < (INT32)hlen)
        //    hlen = bytes;
        counter++;
        r = iesys_crypto_KDFaHmac(hashAlg, hmacKey,
                                  hmacKeySize, counter, label, contextU,
                                  contextV, bitLength, &subKey[0], &hlen);
        return_if_error(r, "Error");
    }
    if ((bitLength % 8) != 0)
        outKey[0] &= ((1 << (bitLength % 8)) - 1);
    if (counterInOut != NULL)
        *counterInOut = counter;
    LOGBLOB_DEBUG(outKey, (bitLength + 7) / 8, "IESYS KDFa key");
    return TPM2_RC_SUCCESS;
}

/** Compute random TPM2B data.
 *
 * The random data will be generated and written to a passed TPM2B structure.
 * @param[out] nonce The TPM2B structure for the random data (caller-allocated).
 * @param[in] num_bytes The number of bytes to be generated.
 * @retval TSS2_RC_SUCCESS on success.
 */
TSS2_RC
iesys_cryptogcry_random2b(TPM2B_NONCE * nonce, size_t num_bytes)
{
    if (num_bytes == 0) {
        nonce->size = sizeof(TPMU_HA);
    } else {
        nonce->size = num_bytes;
    }
    /*
     * possible values for random level:
     *  GCRY_WEAK_RANDOM GCRY_STRONG_RANDOM  GCRY_VERY_STRONG_RANDOM
     */
    gcry_randomize(&nonce->buffer[0], nonce->size, GCRY_STRONG_RANDOM);
    return TSS2_RC_SUCCESS;
}

/** Compute KDFe as described in TPM spec part 1 C 6.1
 *
 * @param hashAlg [in] The nameAlg of the recipient key.
 * @param Z [in] the x coordinate (xP) of the product (P) of a public point and a
 *       private key.
 * @param label [in] KDF label.
 * @param partyUInfo [in] The x-coordinate of the secret exchange value (Qe,U).
 * @param partyVInfo [in] The x-coordinate of a public key (Qs,V).
 * @param bit_size [in] Bit size of generated key.
 * @param key [out] Key buffer.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters
 * @retval TSS2_ESYS_RC_MEMORY Memory cannot be allocated.
 */
TSS2_RC
iesys_cryptogcry_KDFe(TPM2_ALG_ID hashAlg,
                      TPM2B_ECC_PARAMETER *Z,
                      const char *label,
                      TPM2B_ECC_PARAMETER *partyUInfo,
                      TPM2B_ECC_PARAMETER *partyVInfo,
                      UINT32 bit_size,
                      BYTE *key)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t hash_len;
    INT16 byte_size = (INT16)((bit_size +7) / 8);
    BYTE *stream = key;
    IESYS_CRYPTO_CONTEXT_BLOB *cryptoContext;
    BYTE counter_buffer[4];
    UINT32 counter = 0;
    size_t offset;

    LOG_DEBUG("IESYS KDFe hashAlg: %i label: %s bitLength: %i",
              hashAlg, label, bit_size);
    LOGBLOB_DEBUG(&partyUInfo->buffer[0], partyUInfo->size, "partyUInfo");
    LOGBLOB_DEBUG(&partyVInfo->buffer[0], partyVInfo->size, "partyVInfo");
    r = iesys_crypto_hash_get_digest_size(hashAlg, &hash_len);
    return_if_error(r, "Hash algorithm not supported.");

    if(hashAlg == TPM2_ALG_NULL || byte_size == 0) {
        LOG_DEBUG("Bad parameters for KDFe");
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    /* Fill seed key with hash of counter, Z, label, partyUInfo, and partyVInfo */
    for (; byte_size > 0; stream = &stream[hash_len], byte_size = byte_size - hash_len)
        {
            counter ++;
            r = iesys_crypto_hash_start(&cryptoContext, hashAlg);
            return_if_error(r, "Error hash start");

            offset = 0;
            r = Tss2_MU_UINT32_Marshal(counter, &counter_buffer[0], 4, &offset);
            goto_if_error(r, "Error marshaling counter", error);

            r = iesys_crypto_hash_update(cryptoContext, &counter_buffer[0], 4);
            goto_if_error(r, "Error hash update", error);

            if (Z != NULL) {
                r = iesys_crypto_hash_update2b(cryptoContext, (TPM2B *) Z);
                goto_if_error(r, "Error hash update2b", error);
            }

            if (label != NULL) {
                size_t lsize = strlen(label) + 1;
                r = iesys_crypto_hash_update(cryptoContext, (uint8_t *) label, lsize);
                goto_if_error(r, "Error hash update", error);
            }

            if (partyUInfo != NULL) {
                r = iesys_crypto_hash_update2b(cryptoContext, (TPM2B *) partyUInfo);
                goto_if_error(r, "Error hash update2b", error);
            }

            if (partyVInfo != NULL) {
                r = iesys_crypto_hash_update2b(cryptoContext,  (TPM2B *) partyVInfo);
               goto_if_error(r, "Error hash update2b", error);
            }
            r = iesys_crypto_hash_finish(&cryptoContext, (uint8_t *) stream, &hash_len);
            goto_if_error(r, "Error", error);
        }
    LOGBLOB_DEBUG(key, bit_size/8, "Result KDFe");
    if((bit_size % 8) != 0)
        key[0] &= ((1 << (bit_size % 8)) - 1);
    return r;

 error:
    iesys_crypto_hmac_abort(&cryptoContext);
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
iesys_cryptogcry_pk_encrypt(TPM2B_PUBLIC * key,
                            size_t in_size,
                            BYTE * in_buffer,
                            size_t max_out_size,
                            BYTE * out_buffer,
                            size_t * out_size, const char *label)
{
    TSS2_RC r;
    gcry_error_t err;
    char *hash_alg;
    size_t lsize = 0;
    BYTE exponent[4] = { 0x00, 0x01, 0x00, 0x01 };
    char *padding;
    gcry_sexp_t sexp_data, sexp_key, sexp_cipher, sexp_cipher_a;
    if (label != NULL)
        lsize = strlen(label) + 1;
    switch (key->publicArea.nameAlg) {
    case TPM2_ALG_SHA1:
        hash_alg = "sha1";
        break;
    case TPM2_ALG_SHA256:
        hash_alg = "sha256";
        break;
    default:
        LOG_ERROR("Hash alg not implemented");
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    switch (key->publicArea.parameters.rsaDetail.scheme.scheme) {
    case TPM2_ALG_NULL:
        padding = "raw";
        break;
    case TPM2_ALG_RSAES:
        padding = "pkcs1";
        break;
    case TPM2_ALG_OAEP:
        padding = "oaep";
        break;
    default:
        LOG_ERROR("Illegal RSA scheme");
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    size_t offset = 0;
    r = Tss2_MU_UINT32_Marshal(key->publicArea.parameters.rsaDetail.exponent,
                               &exponent[0], sizeof(UINT32), &offset);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Marsahling");
        return r;
    }
    err = gcry_sexp_build(&sexp_data, NULL,
                          "(data (flags %s) (hash-algo %s) (label %b) (value %b) )",
                          padding, hash_alg, lsize, label, (int)in_size,
                          in_buffer);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_sexp_build");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    err = gcry_sexp_build(&sexp_key, NULL, "(public-key (rsa (n %b) (e %b)))",
                          (int)key->publicArea.unique.rsa.size,
                          &key->publicArea.unique.rsa.buffer[0], 4, exponent);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_sexp_build");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    err = gcry_pk_encrypt(&sexp_cipher, sexp_data, sexp_key);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf (stderr, "Failure: %s/%s\n",
                 gcry_strsource (err),
                 gcry_strerror (err));
        LOG_ERROR("Function gcry_pk_encrypt");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    sexp_cipher_a = gcry_sexp_find_token(sexp_cipher, "a", 0);
    gcry_mpi_t mpi_cipher =
        gcry_sexp_nth_mpi(sexp_cipher_a, 1, GCRYMPI_FMT_USG);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, &out_buffer[0], max_out_size,
                         out_size, mpi_cipher);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_mpi_print");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    free(sexp_data);
    free(sexp_key);
    free(sexp_cipher);
    free(sexp_cipher_a);
    return TSS2_RC_SUCCESS;
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
iesys_cryptogcry_get_ecdh_point(TPM2B_PUBLIC *key,
                                size_t max_out_size,
                                TPM2B_ECC_PARAMETER *Z,
                                TPMS_ECC_POINT *Q,
                                BYTE * out_buffer,
                                size_t * out_size)
{
/*
 * Format strings for some gcrypt sexps have to be created with sprintf due to
 * a bug in libgcrypt. %s does not work in libgcypt with these sexps.
 */
#define SEXP_GENKEY_ECC  "(genkey (ecc (curve %s)))"
#define SEXP_ECC_POINT "(ecc (curve %s) (q.x  %sb) (q.y %sb))"

    TSS2_RC r;
    char *curveId;
    gcry_sexp_t mpi_tpm_sq = NULL;     /* sexp for public part of TPM  key*/
    gcry_sexp_t mpi_sd = NULL;         /* sexp for private part of ephemeral key */
    gcry_sexp_t mpi_s_pub_q = NULL;    /* sexp for public part of ephemeral key */
    gcry_mpi_point_t mpi_q = NULL;     /* public point of ephemeral key */
    gcry_mpi_point_t mpi_tpm_q = NULL; /* public point of TPM key */
    gcry_mpi_t mpi_d = NULL;           /* private part of ephemeral key */
    gcry_mpi_point_t mpi_qd = NULL;    /* result of mpi_tpm_q * mpi_d */
    gcry_ctx_t ctx = NULL;             /* context for ec curves */
    size_t size_x, size_y;
    size_t offset = 0;
    gcry_mpi_t mpi_x = gcry_mpi_new(521);  /* big number for x coordinate */
    gcry_mpi_t mpi_y = gcry_mpi_new(521);  /* big number for y coordinate */

    /* Set libcrypt constant fo curve type */
    switch (key->publicArea.parameters.eccDetail.curveID) {
    case TPM2_ECC_NIST_P192:
        curveId = "\"NIST P-192\"";
        break;
    case TPM2_ECC_NIST_P224:
        curveId = "\"NIST P-224\"";
        break;
    case TPM2_ECC_NIST_P256:
        curveId = "\"NIST P-256\"";
        break;
    case TPM2_ECC_NIST_P384:
        curveId = "\"NIST P-384\"";
        break;
    case TPM2_ECC_NIST_P521:
        curveId = "\"NIST P-521\"";
        break;
    default:
        LOG_ERROR("Illegal ECC curve ID");
        return TSS2_ESYS_RC_BAD_VALUE;
    }

    /* compute ephemeral ecc key */
    gcry_sexp_t ekey_spec = NULL, ekey_pair = NULL;
    { /* scope for sexp_ecc_key */
        char sexp_ecc_key [sizeof(SEXP_GENKEY_ECC)+strlen(curveId)
                           -1];  // -1 = (-2 for %s +1 for \0)

        if (sprintf(&sexp_ecc_key[0], SEXP_GENKEY_ECC, curveId) < 1) {
            goto_error(r, TSS2_ESYS_RC_MEMORY, "asprintf", cleanup);
        }

        if (gcry_sexp_build(&ekey_spec, NULL,
                            sexp_ecc_key) != GPG_ERR_NO_ERROR) {
            goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "gcry_sexp_build", cleanup);
        }
    }

    if (gcry_pk_genkey (&ekey_pair, ekey_spec) != GPG_ERR_NO_ERROR) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create ephemeral ecc key",
                   cleanup);
    }

    /* Get private ephemeral key d  */
    mpi_sd = gcry_sexp_find_token(ekey_pair, "d", 0);
    if (mpi_sd == NULL) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Get private part of ecc key", cleanup);
    }
    mpi_d = gcry_sexp_nth_mpi(mpi_sd, 1, GCRYMPI_FMT_USG);
    if (mpi_d == NULL) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Get private part of ecc key from sexp", cleanup);
    }

    /* Construct ephemeral public key */
    mpi_s_pub_q = gcry_sexp_find_token(ekey_pair, "public-key", 0);
    if (mpi_s_pub_q == NULL) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Get public part ecc key",
                   cleanup);
    }

    if (gcry_mpi_ec_new (&ctx, mpi_s_pub_q, curveId) != GPG_ERR_NO_ERROR) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create ec", cleanup);
    }
    mpi_q =  gcry_mpi_ec_get_point ("q", ctx, 1);
    if (mpi_q == NULL) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Get ecc point", cleanup);
    }

    /* Check whether point is on curve */
    if (!gcry_mpi_ec_curve_point(mpi_q, ctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Point not on curve", cleanup);
    }

    /* Store ephemeral public key in Q */
    if (gcry_mpi_ec_get_affine (mpi_x, mpi_y, mpi_q, ctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Point is at infinity",
                   cleanup);
    }

    if (gcry_mpi_print(GCRYMPI_FMT_USG, &Q->x.buffer[0], max_out_size,
                       &size_x, mpi_x) != GPG_ERR_NO_ERROR) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Get x part of point",
                   cleanup);
    }

    if (gcry_mpi_print(GCRYMPI_FMT_USG, &Q->y.buffer[0], max_out_size,
                       &size_y, mpi_y) != GPG_ERR_NO_ERROR) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Get y part of point",
                   cleanup);
    }
    Q->x.size = size_x;
    Q->y.size = size_y;
    SAFE_FREE(ctx);
    { /* scope for sexp_point */

        /* Get public point from TPM key */
        char sexp_point [sizeof(SEXP_ECC_POINT) + strlen(curveId)
                         + key->publicArea.unique.ecc.x.size
                         + key->publicArea.unique.ecc.y.size
                         - 5];  /* -1 = (-4 for 2*%sb -2 for %s +1 for \0) */

        if (sprintf(&sexp_point[0], SEXP_ECC_POINT,
                    curveId, "%", "%") <1 ) {
            goto_error(r, TSS2_ESYS_RC_MEMORY, "asprintf", cleanup);
        }

        if ( gcry_sexp_build(&mpi_tpm_sq, NULL,
                              sexp_point,
                              key->publicArea.unique.ecc.x.size,
                              &key->publicArea.unique.ecc.x.buffer[0],
                              key->publicArea.unique.ecc.y.size,
                             &key->publicArea.unique.ecc.y.buffer[0])) {
            goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                       "Function gcry_mpi_scan", cleanup);

        }
    }
    offset = 0;
    r = Tss2_MU_TPMS_ECC_POINT_Marshal(Q,  &out_buffer[0], max_out_size, &offset);
    return_if_error(r, "Error marshaling");
    *out_size = offset;

    /* Multiply d and Q */
    if (gcry_mpi_ec_new (&ctx, mpi_tpm_sq, curveId)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "create ec curve", cleanup);
    }
    mpi_tpm_q =  gcry_mpi_ec_get_point ("q", ctx, 1);
    mpi_qd = gcry_mpi_point_new(256);
    gcry_mpi_ec_mul(mpi_qd , mpi_d, mpi_tpm_q, ctx);

    /* Store the x coordinate of d*Q in Z which will be used for KDFe */
    if (gcry_mpi_ec_get_affine (mpi_x, mpi_y, mpi_qd, ctx)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Point is at infinity", cleanup);
    }

    if (gcry_mpi_print(GCRYMPI_FMT_USG, &Z->buffer[0], TPM2_MAX_ECC_KEY_BYTES,
                       &size_x, mpi_x)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Get x coordinate d*Q", cleanup);
    }

    Z->size = size_x;
    LOGBLOB_DEBUG(&Z->buffer[0], size_x, "Z (Q*d)");

 cleanup:
    SAFE_FREE(ctx);
    SAFE_FREE(mpi_x);
    SAFE_FREE(mpi_y);
    SAFE_FREE(mpi_tpm_q);
    SAFE_FREE(mpi_qd);
    SAFE_FREE(mpi_q);
    SAFE_FREE(mpi_tpm_q);
    SAFE_FREE(mpi_tpm_sq);
    SAFE_FREE(ekey_spec);
    SAFE_FREE(mpi_s_pub_q);

    return r;
}

/** Initialize AES context for encryption / decryption.
 *
 * @param[out] handle for AES context
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation.
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CBC or CFB).
 * @param[in] iv_len Length of initialization vector (iv) in byte.
 * @param[in] iv The initialization vector.
 * @retval TSS2_RC_SUCCESS on success, or TSS2_ESYS_RC_BAD_VALUE for invalid
 *         parameters, TSS2_ESYS_RC_GENERAL_FAILURE for errors of the crypto
 *         library.
 */
TSS2_RC
iesys_cryptogcry_sym_aes_init(gcry_cipher_hd_t * cipher_hd,
                              uint8_t * key,
                              TPM2_ALG_ID tpm_sym_alg,
                              TPMI_AES_KEY_BITS key_bits,
                              TPM2_ALG_ID tpm_mode,
                              size_t iv_len, uint8_t * iv)
{

    LOGBLOB_TRACE(key, (key_bits + 7) / 8, "IESYS AES key");
    LOGBLOB_TRACE(iv, iv_len, "IESYS AES iv");
    int algo, mode, len;
    size_t key_len = 0;
    gcry_error_t err;
    switch (tpm_sym_alg) {
    case TPM2_ALG_AES:
        switch (key_bits) {
        case 128:
            algo = GCRY_CIPHER_AES128;
            len = 128;
            break;
        case 192:
            algo = GCRY_CIPHER_AES192;
            len = 192;
            break;
        case 256:
            algo = GCRY_CIPHER_AES256;
            len = 256;
            break;
        default:
            LOG_ERROR("Illegal key length.");
            return TSS2_ESYS_RC_BAD_VALUE;
        }
        switch (tpm_mode) {
        case TPM2_ALG_CBC:
            mode = GCRY_CIPHER_MODE_CBC;
            break;
        case TPM2_ALG_CFB:
            mode = GCRY_CIPHER_MODE_CFB;
            break;
        default:
            LOG_ERROR("Illegal symmetric algorithm.");
            return TSS2_ESYS_RC_BAD_VALUE;
        }
        break;
    default:
        LOG_ERROR("Illegal symmetric algorithm.");
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    key_len = (len + 7) / 8;
    err = gcry_cipher_open(cipher_hd, algo, mode, 0);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Opening gcrypt context");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    if (iv_len != 0) {
        err = gcry_cipher_setiv(*cipher_hd, &iv[0], iv_len);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_cipher_setiv");
            return TSS2_ESYS_RC_GENERAL_FAILURE;
        }
    }
    err = gcry_cipher_setkey(*cipher_hd, key, key_len);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_cipher_setkey");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    return TSS2_RC_SUCCESS;
}

/** Encrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CBC or CFB).
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
iesys_cryptogcry_sym_aes_encrypt(uint8_t * key,
                                 TPM2_ALG_ID tpm_sym_alg,
                                 TPMI_AES_KEY_BITS key_bits,
                                 TPM2_ALG_ID tpm_mode,
                                 size_t blk_len,
                                 uint8_t * buffer,
                                 size_t buffer_size,
                                 uint8_t * iv)
{
    gcry_cipher_hd_t cipher_hd;
    gcry_error_t err;
    TSS2_RC r;

    if (key == NULL || buffer == NULL) {
        LOG_ERROR("Bad reference");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    r = iesys_cryptogcry_sym_aes_init(&cipher_hd, key, tpm_sym_alg,
                                      key_bits, tpm_mode, blk_len, iv);
    if (r != TSS2_RC_SUCCESS)
        return r;
    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES input");
    err = gcry_cipher_encrypt(cipher_hd, buffer, buffer_size, NULL, 0);
    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES output");
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_cipher_encrypt");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    gcry_cipher_close(cipher_hd);
    return TSS2_RC_SUCCESS;
}

/** Decrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CBC or CFB).
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
iesys_cryptogcry_sym_aes_decrypt(uint8_t * key,
                                 TPM2_ALG_ID tpm_sym_alg,
                                 TPMI_AES_KEY_BITS key_bits,
                                 TPM2_ALG_ID tpm_mode,
                                 size_t blk_len,
                                 uint8_t * buffer,
                                 size_t buffer_size,
                                 uint8_t * iv)
{
    gcry_cipher_hd_t cipher_hd;
    gcry_error_t err;
    TSS2_RC r;

    if (tpm_sym_alg != TPM2_ALG_AES) {
        LOG_ERROR("AES expected");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }

    if (key == NULL || buffer == NULL) {
        LOG_ERROR("Bad reference");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    r = iesys_cryptogcry_sym_aes_init(&cipher_hd, key, tpm_sym_alg,
                                      key_bits, tpm_mode, blk_len, iv);
    if (r != TSS2_RC_SUCCESS)
        return r;
    err = gcry_cipher_decrypt(cipher_hd, buffer, buffer_size, NULL, 0);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_cipher_decrypt");
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    gcry_cipher_close(cipher_hd);
    return TSS2_RC_SUCCESS;
}

/** Encryption/Decryption using XOR obfuscation.
 *
 * The application of this function to data encrypted with this function will
 * produce the origin data. The key for XOR obfuscation will be derived with
 * KDFa form the passed key the session nonces, and the hash algorithm.
 * @param[in] hash_alg The algorithm used for key derivation.
 * @param[in] key key used for obfuscation
 * @param[in] key_size Key size in bits.
 * @param[in] contextU, contextV are used for construction of a binary string
 *            containing information related to the derived key.
 * @param[in,out] data Data to be encrypted/decrypted the result will be
 *                will be stored in this buffer.
 * @param[in] data_size size of data to be encrypted/decrypted.
 * @retval TSS2_RC_SUCCESS on success, or TSS2_ESYS_RC_BAD_VALUE and
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 */
TSS2_RC
iesys_xor_parameter_obfuscation(TPM2_ALG_ID hash_alg,
                                uint8_t *key,
                                size_t key_size,
                                TPM2B_NONCE * contextU,
                                TPM2B_NONCE * contextV,
                                BYTE *data,
                                size_t data_size)
{
    TSS2_RC r;
    uint32_t counter = 0;
    BYTE  kdfa_result[TPM2_MAX_DIGEST_BUFFER];
    size_t digest_size;
    size_t data_size_bits = data_size * 8;
    size_t rest_size = data_size;
    BYTE *kdfa_byte_ptr;

    if (key == NULL || data == NULL) {
        LOG_ERROR("Bad reference");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    r = iesys_crypto_hash_get_digest_size(hash_alg, &digest_size);
    return_if_error(r, "Hash alg not supported");
    while(rest_size > 0) {
        r = iesys_crypto_KDFa(hash_alg, key, key_size, "XOR",
                              contextU, contextV, data_size_bits, &counter,
                              kdfa_result, TRUE);
        return_if_error(r, "iesys_crypto_KDFa failed");
        /* XOR next data sub block with KDFa result  */
        kdfa_byte_ptr = kdfa_result;
        LOGBLOB_TRACE(data, data_size, "Parameter data before XOR");
        for(size_t i = digest_size < rest_size ? digest_size : rest_size; i > 0;
            i--)
            *data++ ^= *kdfa_byte_ptr++;
        LOGBLOB_TRACE(data, data_size, "Parameter data after XOR");
        rest_size = rest_size < digest_size ? 0 : rest_size - digest_size;
    }
    return TSS2_RC_SUCCESS;
}
