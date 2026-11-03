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
#include "tss2_crypto.h"  // for IFAPI_CRYPTO_CONTEXT_BLOB

#define LOGMODULE fapi
#include "util/log.h" // for return_if_null, goto_error, goto_if...

/** Context to hold temporary values for ifapi_crypto */
typedef struct IFAPI_CRYPTO_CONTEXT {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /** The currently used hash algorithm */
    const EVP_MD *osslHashAlgorithm;
#else
    OSSL_LIB_CTX *libctx;
    /** The currently used hash algorithm */
    EVP_MD *osslHashAlgorithm;
#endif
    /** The hash engine's context */
    EVP_MD_CTX *osslContext;
    /** The size of the hash's digest */
    size_t hashSize;
} IFAPI_CRYPTO_CONTEXT;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/**
 * Converts a TSS hash algorithm identifier into an OpenSSL hash algorithm
 * identifier object.
 *
 * @param[in] hashAlgorithm The TSS hash algorithm identifier to convert
 *
 * @retval A suitable OpenSSL identifier object if one could be found
 * @retval NULL if no suitable identifier object could be found
 */
const EVP_MD *
ifapi_get_ossl_hash_md(TPM2_ALG_ID hashAlgorithm) {
    switch (hashAlgorithm) {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
    case TPM2_ALG_SHA256:
        return EVP_sha256();
    case TPM2_ALG_SHA384:
        return EVP_sha384();
    case TPM2_ALG_SHA512:
        return EVP_sha512();
#if HAVE_EVP_SM3 && !defined(OPENSSL_NO_SM3)
    case TPM2_ALG_SM3_256:
        return EVP_sm3();
#endif
    default:
        return NULL;
    }
}
#else
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
const char *
ifapi_get_hash_md(TPM2_ALG_ID hashAlgorithm) {
    switch (hashAlgorithm) {
    case TPM2_ALG_SHA1:
        return "SHA1";
    case TPM2_ALG_SHA256:
        return "SHA256";
    case TPM2_ALG_SHA384:
        return "SHA384";
    case TPM2_ALG_SHA512:
        return "SHA512";
    case TPM2_ALG_SM3_256:
        return "SM3";
    default:
        return NULL;
    }
}
#endif
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
ifapi_hash_get_digest_size(TPM2_ALG_ID hashAlgorithm) {
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

static void
ifapi_crypto_context_free(IFAPI_CRYPTO_CONTEXT *ctx) {
    if (!ctx)
        return;

    if (ctx->osslContext) {
        EVP_MD_CTX_destroy(ctx->osslContext);
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (ctx->osslHashAlgorithm) {
        EVP_MD_free(ctx->osslHashAlgorithm);
    }
    if (ctx->libctx) {
        OSSL_LIB_CTX_free(ctx->libctx);
    }
#endif
    SAFE_FREE(ctx);
}

/**
 * Aborts a hash operation and finalizes the hash context. It will be set to
 * NULL.
 *
 * @param[in,out] context The context of the digest object.
 */
void
ifapi_crypto_hash_abort(IFAPI_CRYPTO_CONTEXT_BLOB **context) {
    LOG_TRACE("called for context-pointer %p", context);
    if (context == NULL || *context == NULL) {
        LOG_DEBUG("Null-Pointer passed");
        return;
    }

    ifapi_crypto_context_free(*context);
    *context = NULL;
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
ifapi_crypto_hash_update(IFAPI_CRYPTO_CONTEXT_BLOB *context, const uint8_t *buffer, size_t size) {
    /* Check for NULL parameters */
    return_if_null(context, "context is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(buffer, "buffer is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    LOG_DEBUG("called for context %p, buffer %p and size %zd", context, buffer, size);

    /* Update the digest */
    IFAPI_CRYPTO_CONTEXT *mycontext = (IFAPI_CRYPTO_CONTEXT *)context;
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
ifapi_crypto_hash_finish(IFAPI_CRYPTO_CONTEXT_BLOB **context, uint8_t *digest, size_t *digestSize) {
    TSS2_RC r = TSS2_RC_SUCCESS;

    /* Check for NULL parameters */
    return_if_null(context, "context is NULL", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(digest, "digest is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    unsigned int computedDigestSize = 0;

    LOG_TRACE("called for context-pointer %p, digest %p and size-pointer %p", context, digest,
              digestSize);
    /* Compute the digest */
    IFAPI_CRYPTO_CONTEXT *mycontext = *context;
    if (1 != EVP_DigestFinal_ex(mycontext->osslContext, digest, &computedDigestSize)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "OSSL error.", cleanup);
    }

    if (computedDigestSize != mycontext->hashSize) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Invalid size computed by EVP_DigestFinal_ex",
                   cleanup);
    }

    LOGBLOB_DEBUG(digest, mycontext->hashSize, "finish hash");

    if (digestSize != NULL) {
        *digestSize = mycontext->hashSize;
    }

cleanup:

    /* Finalize the hash context */
    ifapi_crypto_context_free(mycontext);
    *context = NULL;

    return r;
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
ifapi_crypto_hash_start(IFAPI_CRYPTO_CONTEXT_BLOB **context, TPM2_ALG_ID hashAlgorithm) {
    /* Check for NULL parameters */
    return_if_null(context, "context is NULL", TSS2_FAPI_RC_BAD_REFERENCE);

    /* Initialize the hash context */
    TSS2_RC r = TSS2_RC_SUCCESS;
    LOG_DEBUG("call: context=%p hashAlg=%" PRIu16, context, hashAlgorithm);
    IFAPI_CRYPTO_CONTEXT *mycontext = NULL;
    mycontext = calloc(1, sizeof(IFAPI_CRYPTO_CONTEXT));
    return_if_null(mycontext, "Out of memory", TSS2_FAPI_RC_MEMORY);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!(mycontext->osslHashAlgorithm = ifapi_get_ossl_hash_md(hashAlgorithm))) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   hashAlgorithm);
    }
#else
    /* The TPM2 provider may be loaded in the global library context.
     * As we don't want the TPM to be called for these operations, we have
     * to initialize own library context with the default provider. */
    mycontext->libctx = OSSL_LIB_CTX_new();
    goto_if_null(mycontext->libctx, "Out of memory", TSS2_FAPI_RC_MEMORY, cleanup);

    if (!(mycontext->osslHashAlgorithm
          = EVP_MD_fetch(mycontext->libctx, ifapi_get_hash_md(hashAlgorithm), NULL))) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   hashAlgorithm);
    }
#endif

    if (!(mycontext->hashSize = ifapi_hash_get_digest_size(hashAlgorithm))) {
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Unsupported hash algorithm (%" PRIu16 ")", cleanup,
                   hashAlgorithm);
    }

    if (!(mycontext->osslContext = EVP_MD_CTX_create())) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Error EVP_MD_CTX_create", cleanup);
    }

    if (1 != EVP_DigestInit_ex(mycontext->osslContext, mycontext->osslHashAlgorithm, NULL)) {
        goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Error EVP_DigestInit_ex", cleanup);
    }

    *context = (IFAPI_CRYPTO_CONTEXT_BLOB *)mycontext;
    return TSS2_RC_SUCCESS;

cleanup:
    ifapi_crypto_context_free(mycontext);
    *context = NULL;
    return r;
}
