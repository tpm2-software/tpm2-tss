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
#include <sapi/tpm20.h>
#ifndef TSS2_API_VERSION_1_2_1_108
#error Version missmatch among TSS2 header files !
#endif                          /* TSS2_API_VERSION_1_2_1_108 */

#include <sapi/tss2_sys.h>
#include <sysapi_util.h>
#define LOGMODULE sys
#include "log/log.h"

#include "esys_crypto.h"
#include "esys_iutil.h"

#include <gcrypt.h>

#include <stdarg.h>

/** Context to hold temporary values for iesys_crypto */
typedef struct _IESYS_CRYPTO_CONTEXT {
    enum {
        IESYS_CRYPTOGCRY_TYPE_HASH = 1,
        IESYS_CRYPTOGCRY_TYPE_HMAC,
    } type; /**< The type of hontext to hold; hash or hmac */
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

/** Provide the digest size for a given hash algorithm
 *
 * This function provides the size of the digest for a given hash algorithm
 *
 * @param hashAlg [in] The hash algorithm to get the size for
 * @param size [out] The side of a digest of the hash algorithm
 * @returnval TSS2_RC_SUCCESS on success
 * @returnval TSS2_SYS_RC_BAD_VALUE if hashAlg is unknown or unsupported
 */
TSS2_RC
iesys_crypto_hash_get_digest_size(TPM2_ALG_ID hashAlg, size_t * size)
{
    LOG_TRACE("call: hashAlg=%"PRIu16" size=%p", hashAlg, size);
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
        return TSS2_SYS_RC_BAD_VALUE;
    }
    LOG_TRACE("return: *size=%zu", *size);
    return TSS2_RC_SUCCESS;
}


TSS2_RC
iesys_cryptogcry_hash_start(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                            TPM2_ALG_ID hashAlg)
{
    LOG_TRACE("call: context=%p hashAlg=%"PRIu16, context, hashAlg);
    return_if_null(context, "Context is NULL", TSS2_SYS_RC_BAD_REFERENCE);
    IESYS_CRYPTOGCRY_CONTEXT *mycontext;
    mycontext = calloc(1, sizeof(IESYS_CRYPTOGCRY_CONTEXT));
    return_if_null(mycontext, "Out of Memory", TSS2_SYS_RC_GENERAL_FAILURE);
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
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    int hash_len = gcry_md_get_algo_dlen(mycontext->hash.gcry_hash_alg);
    if (hash_len <= 0) {
        LOG_ERROR("Unsupported hash algorithm (%"PRIu16")", hashAlg);
        free(mycontext);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    mycontext->hash.hash_len = hash_len;

    gcry_error_t r = gcry_md_open(&mycontext->hash.gcry_context,
                             mycontext->hash.gcry_hash_alg, 0);
    if (r != 0) {
        LOG_ERROR("GCry error.");
        free(mycontext);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    *context = (IESYS_CRYPTO_CONTEXT_BLOB *) mycontext;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_hash_update(IESYS_CRYPTO_CONTEXT_BLOB * context,
                             const uint8_t * buffer, size_t size)
{
    LOG_TRACE("called for context %p, buffer %p and size %zd", context, buffer,
              size);
    if (context == NULL || buffer == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext = (IESYS_CRYPTOGCRY_CONTEXT *) context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HASH) {
        LOG_ERROR("bad context");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    LOGBLOB_TRACE(buffer, size, "Updating hash with");

    gcry_md_write(mycontext->hash.gcry_context, buffer, size);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_hash_update2b(IESYS_CRYPTO_CONTEXT_BLOB * context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret = iesys_cryptogcry_hash_update(context, &b->buffer[0], b->size);
    return ret;
}

TSS2_RC
iesys_cryptogcry_hash_finish(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                             uint8_t * buffer, size_t * size)
{
    LOG_TRACE("called for context-pointer %p, buffer %p and size-pointer %p",
              context, buffer, size);
    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext = * context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HASH) {
        LOG_ERROR("bad context");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    if (*size < mycontext->hash.hash_len) {
        LOG_ERROR("Buffer too small");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    uint8_t *cpHash = gcry_md_read(mycontext->hash.gcry_context,
                                   mycontext->hash.gcry_hash_alg);
    if (cpHash == NULL) {
        LOG_ERROR("GCry error.");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    LOGBLOB_TRACE(cpHash, mycontext->hash.hash_len, "read hash result");

    *size = mycontext->hash.hash_len;
    memmove(buffer, cpHash, *size);

    gcry_md_close(mycontext->hash.gcry_context);

    free(mycontext);
    *context = NULL;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_hash_finish2b(IESYS_CRYPTO_CONTEXT_BLOB ** context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || *context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    size_t s = b->size;
    TSS2_RC ret = iesys_cryptogcry_hash_finish(context, &b->buffer[0], &s);
    b->size = s;
    return ret;
}

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
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext =
        calloc(1, sizeof(IESYS_CRYPTOGCRY_CONTEXT));
    if (mycontext == NULL) {
        LOG_ERROR("Out of Memory");
        return TSS2_SYS_RC_GENERAL_FAILURE;
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
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    int hmac_len = gcry_mac_get_algo_maclen(mycontext->hmac.gcry_hmac_alg);
    if (hmac_len <= 0) {
        LOG_ERROR("GCry error.");
        free(mycontext);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    mycontext->type = IESYS_CRYPTOGCRY_TYPE_HMAC;
    mycontext->hmac.hmac_len = hmac_len;

    r = gcry_mac_open(&mycontext->hmac.gcry_context,
                      mycontext->hmac.gcry_hmac_alg, 0, NULL);
    if (r != 0) {
        LOG_ERROR("GCry error.");
        free(mycontext);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    r = gcry_mac_setkey(mycontext->hmac.gcry_context, key, size);
    if (r != 0) {
        LOG_ERROR("GCry error.");
        gcry_mac_close(mycontext->hmac.gcry_context);
        free(mycontext);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    *context = (IESYS_CRYPTO_CONTEXT_BLOB *) mycontext;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_hmac_start2b(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                              TPM2_ALG_ID hmacAlg, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret = iesys_cryptogcry_hmac_start(context, hmacAlg, &b->buffer[0],
                                              b->size);
    return ret;
}

TSS2_RC
iesys_cryptogcry_hmac_update(IESYS_CRYPTO_CONTEXT_BLOB * context,
                             const uint8_t * buffer, size_t size)
{
    LOG_TRACE("called for context %p, buffer %p and size %zd",
              context, buffer, size);
    if (context == NULL || buffer == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext = (IESYS_CRYPTOGCRY_CONTEXT *) context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HMAC) {
        LOG_ERROR("bad context");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    LOGBLOB_TRACE(buffer, size, "Updating hmac with");

    gcry_mac_write(mycontext->hmac.gcry_context, buffer, size);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_hmac_update2b(IESYS_CRYPTO_CONTEXT_BLOB * context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    TSS2_RC ret = iesys_cryptogcry_hmac_update(context, &b->buffer[0], b->size);
    return ret;
}

TSS2_RC
iesys_cryptogcry_hmac_finish(IESYS_CRYPTO_CONTEXT_BLOB ** context,
                             uint8_t * buffer, size_t * size)
{
    LOG_TRACE("called for context-pointer %p, buffer %p and size-pointer %p",
              context, buffer, size);
    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    IESYS_CRYPTOGCRY_CONTEXT *mycontext =
        (IESYS_CRYPTOGCRY_CONTEXT *) * context;
    if (mycontext->type != IESYS_CRYPTOGCRY_TYPE_HMAC) {
        LOG_ERROR("bad context");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    if (*size < mycontext->hmac.hmac_len) {
        LOG_ERROR("Buffer too small");
        return TSS2_SYS_RC_BAD_SIZE;
    }

    TSS2_RC r = gcry_mac_read(mycontext->hmac.gcry_context, buffer, size);
    if (r != 0) {
        LOG_ERROR("GCry error.");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    LOGBLOB_TRACE(buffer, *size, "read hmac result");

    gcry_mac_close(mycontext->hmac.gcry_context);

    free(mycontext);
    *context = NULL;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_hmac_finish2b(IESYS_CRYPTO_CONTEXT_BLOB ** context, TPM2B * b)
{
    LOG_TRACE("called for context-pointer %p and 2b-pointer %p", context, b);
    if (context == NULL || *context == NULL || b == NULL) {
        LOG_ERROR("Null-Pointer passed");
        return TSS2_SYS_RC_BAD_REFERENCE;
    }
    size_t s = b->size;
    TSS2_RC ret = iesys_cryptogcry_hmac_finish(context, &b->buffer[0], &s);
    b->size = s;
    return ret;
}

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
        return TSS2_SYS_RC_BAD_REFERENCE;
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
        return TSS2_SYS_RC_BAD_REFERENCE;
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
        return TSS2_SYS_RC_BAD_REFERENCE;
    }

    uint8_t buffer32[sizeof(uint32_t)];
    size_t buffer32_size = 0;

    IESYS_CRYPTO_CONTEXT_BLOB *cryptoContext;

    TSS2_RC r =
        iesys_crypto_hmac_start(&cryptoContext, alg, hmacKey, hmacKeySize);
    return_if_error(r, "Error");

    r = Tss2_MU_UINT32_Marshal(counter, &buffer32[0], sizeof(UINT32),
                           &buffer32_size);
    goto_if_error(r, "Marshalling", error);
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
    goto_if_error(r, "Marshalling", error);
    r = iesys_crypto_hmac_update(cryptoContext, &buffer32[0], buffer32_size);
    goto_if_error(r, "Error", error);

    r = iesys_crypto_hmac_finish(&cryptoContext, hmac, hmacSize);
    goto_if_error(r, "Error", error);

    return r;

 error:
    iesys_crypto_hmac_abort(&cryptoContext);
    return r;
}

TSS2_RC
iesys_crypto_KDFa(TPM2_ALG_ID hashAlg,
                  uint8_t * hmacKey,
                  size_t hmacKeySize,
                  const char *label,
                  TPM2B_NONCE * contextU,
                  TPM2B_NONCE * contextV,
                  uint32_t bitLength, uint32_t * counterInOut, BYTE * outKey)
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
    bytes = (bitLength + 7) / 8;
    LOG_DEBUG("IESYS KDFa hmac key bytes: %i", bytes);
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

TSS2_RC
iesys_cryptogcry_pk_encrypt(TPM2B_PUBLIC * key,
                            size_t in_size,
                            BYTE * in_buffer,
                            size_t max_out_size,
                            BYTE * out_buffer,
                            size_t * out_size, const char *label)
{
    TSS2_RC r;
    gcry_mpi_t mpi_data;
    gcry_error_t err;
    char *hash_alg;
    size_t lsize = 0;
    BYTE exponent[4] = { 0x00, 0x01, 0x00, 0x01 };
    //gcry_mpi_t mpi_exp;
    char *padding;
    char *curveId;
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
        return TSS2_SYS_RC_BAD_VALUE;
    }
    switch (key->publicArea.type) {
    case TPM2_ALG_RSA:
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
            return TSS2_SYS_RC_BAD_VALUE;
        }
        size_t offset = 0;
        r = Tss2_MU_UINT32_Marshal(key->publicArea.parameters.rsaDetail.exponent,
                                   &exponent[0], sizeof(UINT32), &offset);
        if (r != TSS2_RC_SUCCESS) {
            LOG_ERROR("Marshalling");
            return r;
        }
        err = gcry_sexp_build(&sexp_data, NULL,
                              "(data (flags %s) (hash-algo %s) (label %b) (value %b) )",
                              padding, hash_alg, lsize, label, (int)in_size,
                              in_buffer);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_sexp_build");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        err =
            gcry_sexp_build(&sexp_key, NULL, "(public-key (rsa (n %b) (e %b)))",
                            (int)key->publicArea.unique.rsa.size,
                            &key->publicArea.unique.rsa.buffer[0], 4, exponent);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_sexp_build");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        break;
    case TPM2_ALG_ECC:
        switch (key->publicArea.parameters.eccDetail.curveID) {
        case TPM2_ECC_NIST_P192:
            curveId = "nistp192";
            break;
        case TPM2_ECC_NIST_P224:
            curveId = "nistp224";
            break;
        case TPM2_ECC_NIST_P256:
            curveId = "nistp265";
            break;
        case TPM2_ECC_NIST_P384:
            curveId = "nistp384";
            break;
        case TPM2_ECC_NIST_P521:
            curveId = "nistp521";
            break;
        default:
            LOG_ERROR("Illegal ECC curve ID");
            return TSS2_SYS_RC_BAD_VALUE;
        }
        gcry_mpi_point_t mpi_q = gcry_mpi_point_new(0);
        gcry_mpi_t mpi_x, mpi_y;
        err = gcry_mpi_scan(&mpi_x, GCRYMPI_FMT_USG,
                            &key->publicArea.unique.ecc.x.buffer[0],
                            key->publicArea.unique.ecc.x.size, NULL);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_mpi_scan");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        err = gcry_mpi_scan(&mpi_y, GCRYMPI_FMT_USG,
                            &key->publicArea.unique.ecc.y.buffer[0],
                            key->publicArea.unique.ecc.y.size, NULL);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_mpi_scan");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        gcry_mpi_point_get(mpi_x, mpi_y, NULL, mpi_q);
        err =
            gcry_mpi_scan(&mpi_data, GCRYMPI_FMT_USG, in_buffer, in_size, NULL);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_mpi_scan");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        err = gcry_sexp_build(&sexp_data, NULL, "(data (value %m))", mpi_data);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_sexp_build");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        err = gcry_sexp_build(&sexp_key, NULL,
                              "(public-key (ecc (curve %s) (e %m)))", curveId,
                              mpi_q);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_sexp_build");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        break;
    default:
        LOG_ERROR("Not implemented");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    err = gcry_pk_encrypt(&sexp_cipher, sexp_data, sexp_key);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_pk_encrypt");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    sexp_cipher_a = gcry_sexp_find_token(sexp_cipher, "a", 0);
    gcry_mpi_t mpi_cipher =
        gcry_sexp_nth_mpi(sexp_cipher_a, 1, GCRYMPI_FMT_USG);
    size_t alen;
    const void *a;
    a = gcry_sexp_nth_data(sexp_cipher_a, 1, &alen);
    (void)a;
    (void)alen;
    err = gcry_mpi_print(GCRYMPI_FMT_USG, &out_buffer[0], max_out_size,
                         out_size, mpi_cipher);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_mpi_print");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    free(sexp_data);
    free(sexp_key);
    free(sexp_cipher);
    free(sexp_cipher_a);
    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_pk_decrypt(TPM2B_PUBLIC * key,
                            size_t in_size, BYTE * in_buffer,
                            size_t max_out_size,
                            BYTE * out_buffer,
                            size_t * out_size, const char *label)
{
    gcry_mpi_t mpi_data;
    gcry_error_t err;
    // char *hash_alg;
    // size_t lsize = 0;
    BYTE exponent[4] = { 0x00, 0x01, 0x00, 0x01 };
    //gcry_mpi_t mpi_exp;
    char *padding;
    char *curveId;
    gcry_sexp_t sexp_data, sexp_key, sexp_cipher, sexp_data_value;
    //if (label != NULL)
    //    lsize = strlen(label) + 1;
    switch (key->publicArea.nameAlg) {
    case TPM2_ALG_SHA1:
        // hash_alg = "sha1";
        break;
    case TPM2_ALG_SHA256:
        // hash_alg = "sha256";
        break;
    default:
        LOG_ERROR("Hash alg not implemented");
        return TSS2_SYS_RC_BAD_VALUE;
    }
    switch (key->publicArea.type) {
    case TPM2_ALG_RSA:
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
            return TSS2_SYS_RC_BAD_VALUE;
        }
        size_t offset = 0;
        err =
            gcry_sexp_build(&sexp_cipher, NULL,
                            "(enc-val (flags %s) (rsa (a  %b))", padding,
                            (int)in_size, in_buffer);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_sexp_build");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        err =
            gcry_sexp_build(&sexp_key, NULL, "(public-key (rsa (n %b) (e %b)))",
                            (int)key->publicArea.unique.rsa.size,
                            &key->publicArea.unique.rsa.buffer[0], 4, exponent);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_sexp_build");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        break;
    case TPM2_ALG_ECC:
        switch (key->publicArea.parameters.eccDetail.curveID) {
        case TPM2_ECC_NIST_P192:
            curveId = "nistp192";
            break;
        case TPM2_ECC_NIST_P224:
            curveId = "nistp224";
            break;
        case TPM2_ECC_NIST_P256:
            curveId = "nistp265";
            break;
        case TPM2_ECC_NIST_P384:
            curveId = "nistp384";
            break;
        case TPM2_ECC_NIST_P521:
            curveId = "nistp521";
            break;
        default:
            LOG_ERROR("Illegal ECC curve ID");
            return TSS2_SYS_RC_BAD_VALUE;
        }
        gcry_mpi_point_t mpi_q = gcry_mpi_point_new(0);
        gcry_mpi_t mpi_x, mpi_y;
        err = gcry_mpi_scan(&mpi_x, GCRYMPI_FMT_USG,
                            &key->publicArea.unique.ecc.x.buffer[0],
                            key->publicArea.unique.ecc.x.size, NULL);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_mpi_scan");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        err = gcry_mpi_scan(&mpi_y, GCRYMPI_FMT_USG,
                            &key->publicArea.unique.ecc.y.buffer[0],
                            key->publicArea.unique.ecc.y.size, NULL);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_mpi_scan");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        gcry_mpi_point_get(mpi_x, mpi_y, NULL, mpi_q);
        err =
            gcry_mpi_scan(&mpi_data, GCRYMPI_FMT_USG, in_buffer, in_size, NULL);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_mpi_scan");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        err =
            gcry_sexp_build(&sexp_cipher, NULL, "(enc-val (ecc (a %m)))",
                            mpi_data);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_sexp_build");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        err = gcry_sexp_build(&sexp_key, NULL,
                              "(public-key (ecc (curve %s) (e %m)))", curveId,
                              mpi_q);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_sexp_build");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
        break;
    default:
        LOG_ERROR("Not implemented");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    err = gcry_pk_decrypt(&sexp_data, sexp_cipher, sexp_key);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function  gcry_pk_decrypt");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    sexp_data_value = gcry_sexp_find_token(sexp_data, "value", 0);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_sexp_find_token");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    mpi_data = gcry_sexp_nth_mpi(sexp_data_value, 1, GCRYMPI_FMT_USG);
    size_t vlen;
    const void *v;
    v = gcry_sexp_nth_data(sexp_data_value, 1, &vlen);
    (void)v;
    (void)vlen;
    err =
        gcry_mpi_print(GCRYMPI_FMT_USG, &out_buffer[0], max_out_size, out_size,
                       mpi_data);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_mpi_print");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    free(sexp_data);
    free(sexp_key);
    free(sexp_cipher);
    free(sexp_data_value);
    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_sym_aes_init(gcry_cipher_hd_t * cipher_hd,
                              uint8_t * key,
                              TPM2_ALG_ID tpm_sym_alg,
                              TPMI_AES_KEY_BITS key_bits,
                              TPM2_ALG_ID tpm_mode,
                              size_t blk_len, size_t iv_len, uint8_t * iv)
{

    LOGBLOB_TRACE(key, (key_bits + 7) / 8, "IESYS AES key");
    LOGBLOB_TRACE(iv, iv_len, "IESYS AES iv");
    int algo, mode, len;
    //int blk_len = 16;
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
            return TSS2_SYS_RC_BAD_VALUE;
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
            return TSS2_SYS_RC_BAD_VALUE;
        }
        break;
    default:
        LOG_ERROR("Illegal symmetric algorithm.");
        return TSS2_SYS_RC_BAD_VALUE;
    }
    key_len = (len + 7) / 8;
    err = gcry_cipher_open(cipher_hd, algo, mode, 0);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Opening gcrypt context");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    if (iv_len != 0) {
        err = gcry_cipher_setiv(*cipher_hd, &iv[0], blk_len);
        if (err != GPG_ERR_NO_ERROR) {
            LOG_ERROR("Function gcry_cipher_setiv");
            return TSS2_SYS_RC_GENERAL_FAILURE;
        }
    }
    err = gcry_cipher_setkey(*cipher_hd, key, key_len);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_cipher_setkey");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_sym_aes_encrypt(uint8_t * key,
                                 TPM2_ALG_ID tpm_sym_alg,
                                 TPMI_AES_KEY_BITS key_bits,
                                 TPM2_ALG_ID tpm_mode,
                                 size_t blk_len,
                                 uint8_t * buffer,
                                 size_t buffer_size,
                                 uint8_t * iv, size_t iv_len)
{
    gcry_cipher_hd_t cipher_hd;
    //int blk_len = 16;
    gcry_error_t err;
    TSS2_RC r;
    r = iesys_cryptogcry_sym_aes_init(&cipher_hd, key, tpm_sym_alg,
                                      key_bits, tpm_mode, blk_len, iv_len, iv);
    if (r != TSS2_RC_SUCCESS)
        return r;
    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES input");
    err = gcry_cipher_encrypt(cipher_hd, buffer, buffer_size, NULL, 0);
    LOGBLOB_TRACE(buffer, buffer_size, "IESYS AES output");
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_cipher_encrypt");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    gcry_cipher_close(cipher_hd);
    return TSS2_RC_SUCCESS;
}

TSS2_RC
iesys_cryptogcry_sym_aes_decrypt(uint8_t * key,
                                 TPM2_ALG_ID tpm_sym_alg,
                                 TPMI_AES_KEY_BITS key_bits,
                                 TPM2_ALG_ID tpm_mode,
                                 size_t blk_len,
                                 uint8_t * buffer, size_t buffer_size,
                                 uint8_t * iv, size_t iv_len)
{
    gcry_cipher_hd_t cipher_hd;
    //int blk_len = 16;
    gcry_error_t err;
    TSS2_RC r;
    r = iesys_cryptogcry_sym_aes_init(&cipher_hd, key, tpm_sym_alg,
                                      key_bits, tpm_mode, blk_len, iv_len, iv);
    if (r != TSS2_RC_SUCCESS)
        return r;
    err = gcry_cipher_decrypt(cipher_hd, buffer, buffer_size, NULL, 0);
    if (err != GPG_ERR_NO_ERROR) {
        LOG_ERROR("Function gcry_cipher_decrypt");
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    gcry_cipher_close(cipher_hd);
    return TSS2_RC_SUCCESS;
}
