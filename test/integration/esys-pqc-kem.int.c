/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2024, Hewlett Packard Enterprise
 * All rights reserved.
 *******************************************************************************
 */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h> // for NULL, EXIT_FAILURE, EXIT_SUCCESS

#include "test-esys.h" // for EXIT_SKIP
#include <string.h> // for memcmp

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "tss2_common.h"     // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_esys.h"       // for Esys_Free, ESYS_TR_NONE, Esys_FlushContext
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPMA_OBJECT_*, TPM2_ALG_*

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
/* OpenSSL 3.5+ names from obj_mac.h */
#define OSSL_ALG_MLKEM_512  LN_ML_KEM_512
#define OSSL_ALG_MLKEM_768  LN_ML_KEM_768
#define OSSL_ALG_MLKEM_1024 LN_ML_KEM_1024

static const char *
test_mlkem_parms_to_ossl_name(TPMI_MLKEM_PARMS parameterSet) {
    switch (parameterSet) {
    case TPM2_MLKEM_PARMS_512:
        return OSSL_ALG_MLKEM_512;
    case TPM2_MLKEM_PARMS_768:
        return OSSL_ALG_MLKEM_768;
    case TPM2_MLKEM_PARMS_1024:
        return OSSL_ALG_MLKEM_1024;
    default:
        return NULL;
    }
}

static TSS2_RC
test_ossl_mlkem_pub_from_tpm(const TPM2B_PUBLIC *tpmPublicKey, EVP_PKEY **evpPublicKey) {
    TSS2_RC         r = TSS2_RC_SUCCESS;
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM     *params = NULL;
    EVP_PKEY_CTX   *ctx = NULL;
    const char     *alg_name = NULL;

    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(evpPublicKey, "evpPublicKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    alg_name = test_mlkem_parms_to_ossl_name(
        tpmPublicKey->publicArea.parameters.mlkemDetail.parameterSet);
    if (!alg_name) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE, "Unknown ML-KEM parameter set", error_cleanup);
    }

    build = OSSL_PARAM_BLD_new();
    goto_if_null(build, "Out of memory", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (!OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY,
                                          tpmPublicKey->publicArea.unique.mlkem.buffer,
                                          tpmPublicKey->publicArea.unique.mlkem.size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create ML-KEM key parameters", error_cleanup);
    }

    params = OSSL_PARAM_BLD_to_param(build);
    goto_if_null(params, "Create ML-KEM key parameters", TSS2_ESYS_RC_GENERAL_FAILURE,
                 error_cleanup);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    goto_if_null(ctx, "Create ML-KEM EVP_PKEY_CTX", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, evpPublicKey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create ML-KEM EVP_PKEY", error_cleanup);
    }

error_cleanup:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
    return r;
}

static TSS2_RC
test_ossl_mlkem_keygen(TPMI_MLKEM_PARMS parameterSet, EVP_PKEY **keypair) {
    TSS2_RC       r = TSS2_RC_SUCCESS;
    EVP_PKEY_CTX *ctx = NULL;
    const char   *alg_name = NULL;

    return_if_null(keypair, "keypair is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    alg_name = test_mlkem_parms_to_ossl_name(parameterSet);
    if (!alg_name) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "Unknown ML-KEM parameter set");
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    goto_if_null(ctx, "Create ML-KEM EVP_PKEY_CTX", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_generate(ctx, keypair) <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Generate ML-KEM key pair", error_cleanup);
    }

error_cleanup:
    EVP_PKEY_CTX_free(ctx);
    return r;
}

static TSS2_RC
test_get_mlkem_tpm2b_public_from_evp(EVP_PKEY *publicKey, TPM2B_PUBLIC *tpmPublic) {
    TSS2_RC r = TSS2_RC_SUCCESS;
    size_t  key_len = 0;

    return_if_null(publicKey, "publicKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(tpmPublic, "tpmPublic is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    memset(tpmPublic, 0, sizeof(*tpmPublic));
    tpmPublic->publicArea.type = TPM2_ALG_MLKEM;
    tpmPublic->publicArea.nameAlg = TPM2_ALG_SHA256;
    tpmPublic->publicArea.objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_USERWITHAUTH;
    tpmPublic->publicArea.parameters.mlkemDetail.symmetric.algorithm = TPM2_ALG_NULL;

    if (EVP_PKEY_is_a(publicKey, OSSL_ALG_MLKEM_512)) {
        tpmPublic->publicArea.parameters.mlkemDetail.parameterSet = TPM2_MLKEM_PARMS_512;
    } else if (EVP_PKEY_is_a(publicKey, OSSL_ALG_MLKEM_768)) {
        tpmPublic->publicArea.parameters.mlkemDetail.parameterSet = TPM2_MLKEM_PARMS_768;
    } else if (EVP_PKEY_is_a(publicKey, OSSL_ALG_MLKEM_1024)) {
        tpmPublic->publicArea.parameters.mlkemDetail.parameterSet = TPM2_MLKEM_PARMS_1024;
    } else {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "Unknown ML-KEM key type");
    }

    if (!EVP_PKEY_get_raw_public_key(publicKey, NULL, &key_len)) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "Could not get ML-KEM public key size");
    }

    if (key_len > sizeof(tpmPublic->publicArea.unique.mlkem.buffer)) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "ML-KEM public key too large");
    }

    if (!EVP_PKEY_get_raw_public_key(publicKey, tpmPublic->publicArea.unique.mlkem.buffer,
                                     &key_len)) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "Could not get ML-KEM public key");
    }

    tpmPublic->publicArea.unique.mlkem.size = (UINT16)key_len;
    return r;
}

static TSS2_RC
test_ossl_mlkem_encapsulate(EVP_PKEY              *publicKey,
                            TPM2B_KEM_CIPHERTEXT **ciphertext,
                            TPM2B_SHARED_SECRET  **secret) {
    TSS2_RC       r = TSS2_RC_SUCCESS;
    EVP_PKEY_CTX *ctx = NULL;
    size_t        ct_len = 0;
    size_t        ss_len = 0;

    return_if_null(publicKey, "publicKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(ciphertext, "ciphertext is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(secret, "secret is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    *ciphertext = calloc(1, sizeof(**ciphertext));
    goto_if_null(*ciphertext, "Out of memory", TSS2_ESYS_RC_MEMORY, error_cleanup);
    *secret = calloc(1, sizeof(**secret));
    goto_if_null(*secret, "Out of memory", TSS2_ESYS_RC_MEMORY, error_cleanup);

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, publicKey, NULL);
    goto_if_null(ctx, "Create encapsulation context", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len) <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Initialize ML-KEM encapsulation",
                   error_cleanup);
    }

    if (ct_len > sizeof((*ciphertext)->buffer) || ss_len > sizeof((*secret)->buffer)) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE, "ML-KEM output too large", error_cleanup);
    }

    if (EVP_PKEY_encapsulate(ctx, (*ciphertext)->buffer, &ct_len, (*secret)->buffer, &ss_len)
        <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "ML-KEM encapsulation failed", error_cleanup);
    }

    (*ciphertext)->size = (UINT16)ct_len;
    (*secret)->size = (UINT16)ss_len;

error_cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (r != TSS2_RC_SUCCESS) {
        free(*ciphertext);
        free(*secret);
        *ciphertext = NULL;
        *secret = NULL;
    }
    return r;
}

static TSS2_RC
test_ossl_mlkem_decapsulate(EVP_PKEY                   *privateKey,
                            const TPM2B_KEM_CIPHERTEXT *ciphertext,
                            TPM2B_SHARED_SECRET       **secret) {
    TSS2_RC       r = TSS2_RC_SUCCESS;
    EVP_PKEY_CTX *ctx = NULL;
    size_t        ss_len = 0;

    return_if_null(privateKey, "privateKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(ciphertext, "ciphertext is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(secret, "secret is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    *secret = calloc(1, sizeof(**secret));
    goto_if_null(*secret, "Out of memory", TSS2_ESYS_RC_MEMORY, error_cleanup);

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, privateKey, NULL);
    goto_if_null(ctx, "Create decapsulation context", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, NULL, &ss_len, ciphertext->buffer, ciphertext->size) <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Initialize ML-KEM decapsulation",
                   error_cleanup);
    }

    if (ss_len > sizeof((*secret)->buffer)) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE, "ML-KEM shared secret too large", error_cleanup);
    }

    if (EVP_PKEY_decapsulate(ctx, (*secret)->buffer, &ss_len, ciphertext->buffer, ciphertext->size)
        <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "ML-KEM decapsulation failed", error_cleanup);
    }

    (*secret)->size = (UINT16)ss_len;

error_cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (r != TSS2_RC_SUCCESS) {
        free(*secret);
        *secret = NULL;
    }
    return r;
}
#endif

/** Test the ML-KEM encapsulate/decapsulate (KEM) roundtrip.
 *
 * An ML-KEM-1024 primary key is created under the owner hierarchy.
 * Esys_Encapsulate generates a ciphertext and encapsulator shared secret;
 * Esys_Decapsulate recovers the shared secret from the private key.  The
 * two values are compared to confirm correctness.
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_Encapsulate() (M)
 *  - Esys_Decapsulate() (M)
 *  - Esys_FlushContext() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_pqc_kem(ESYS_CONTEXT *esys_context) {
    TSS2_RC r;

    ESYS_TR mlkem_handle = ESYS_TR_NONE;

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_KEM_CIPHERTEXT *ciphertext = NULL;
    TPM2B_SHARED_SECRET  *enc_secret = NULL;
    TPM2B_SHARED_SECRET  *dec_secret = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    EVP_PKEY             *ossl_pub = NULL;
    TPM2B_KEM_CIPHERTEXT *ossl_ciphertext = NULL;
    TPM2B_SHARED_SECRET  *ossl_enc_secret = NULL;
    TPM2B_SHARED_SECRET  *esys_dec_from_ossl = NULL;
#endif

    TPM2B_AUTH authValue = { .size = 5, .buffer = { 1, 2, 3, 4, 5 } };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0, .buffer = {0} },
            .data     = { .size = 0, .buffer = {0} },
        },
    };
    inSensitive.sensitive.userAuth = authValue;

    TPM2B_DATA         outsideInfo = { .size = 0, .buffer = {} };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type    = TPM2_ALG_MLKEM,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                  TPMA_OBJECT_DECRYPT |
                                  TPMA_OBJECT_FIXEDTPM |
                                  TPMA_OBJECT_FIXEDPARENT |
                                  TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = { .size = 0 },
            .parameters.mlkemDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .parameterSet = TPM2_MLKEM_PARMS_1024,
            },
            .unique.mlkem = { .size = 0, .buffer = {} },
        },
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &(TPM2B_AUTH){ .size = 0, .buffer = {} });
    goto_if_error(r, "Error: TR_SetAuth (owner)", error);

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &mlkem_handle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error: CreatePrimary (ML-KEM-1024)", error);

    r = Esys_TR_SetAuth(esys_context, mlkem_handle, &authValue);
    goto_if_error(r, "Error: TR_SetAuth (ML-KEM key)", error);

    r = Esys_Encapsulate(esys_context, mlkem_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                         &ciphertext, &enc_secret);
    goto_if_error(r, "Error: Encapsulate", error);

    r = Esys_Decapsulate(esys_context, mlkem_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         ciphertext, &dec_secret);
    goto_if_error(r, "Error: Decapsulate", error);

    if (enc_secret->size != dec_secret->size
        || memcmp(enc_secret->buffer, dec_secret->buffer, enc_secret->size) != 0) {
        LOG_ERROR("KEM roundtrip FAILED: shared secrets do not match.");
        goto error;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    /* Interop #1: OSSL encapsulate using TPM public key, then TPM decapsulate */
    r = test_ossl_mlkem_pub_from_tpm(outPublic, &ossl_pub);
    goto_if_error(r, "Error: Convert TPM ML-KEM public key for OpenSSL", error);

    r = test_ossl_mlkem_encapsulate(ossl_pub, &ossl_ciphertext, &ossl_enc_secret);
    goto_if_error(r, "Error: OpenSSL ML-KEM encapsulate", error);

    r = Esys_Decapsulate(esys_context, mlkem_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         ossl_ciphertext, &esys_dec_from_ossl);
    goto_if_error(r, "Error: Decapsulate (OpenSSL ciphertext)", error);

    if (ossl_enc_secret->size != esys_dec_from_ossl->size
        || memcmp(ossl_enc_secret->buffer, esys_dec_from_ossl->buffer, ossl_enc_secret->size)
               != 0) {
        LOG_ERROR("KEM interop FAILED: OpenSSL encapsulate secret != TPM decapsulate secret.");
        goto error;
    }
#endif

    r = Esys_FlushContext(esys_context, mlkem_handle);
    goto_if_error(r, "Error: FlushContext", error);
    mlkem_handle = ESYS_TR_NONE;

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(ciphertext);
    Esys_Free(enc_secret);
    Esys_Free(dec_secret);
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    EVP_PKEY_free(ossl_pub);
    free(ossl_ciphertext);
    free(ossl_enc_secret);
    Esys_Free(esys_dec_from_ossl);
#endif
    return EXIT_SUCCESS;

error:
    if (mlkem_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, mlkem_handle) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup mlkem_handle failed.");
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(ciphertext);
    Esys_Free(enc_secret);
    Esys_Free(dec_secret);
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    EVP_PKEY_free(ossl_pub);
    free(ossl_ciphertext);
    free(ossl_enc_secret);
    Esys_Free(esys_dec_from_ossl);
#endif
    return EXIT_FAILURE;
}

/**
 * Interop test: OpenSSL keygen -> Esys_LoadExternal(public) -> Esys_Encapsulate,
 * then OpenSSL decapsulate with private key and compare shared secrets.
 */
static int
test_esys_pqc_kem_load_external_ossl_key(ESYS_CONTEXT *esys_context) {
#if OPENSSL_VERSION_NUMBER < 0x30500000L
    UNUSED(esys_context);
    LOG_WARNING("Skipping ML-KEM OSSL interop test: requires OpenSSL 3.5+");
    return EXIT_SUCCESS;
#else
    TSS2_RC               r;
    EVP_PKEY             *ossl_keypair = NULL;
    TPM2B_PUBLIC          inPublic = { 0 };
    ESYS_TR               loaded_handle = ESYS_TR_NONE;
    TPM2B_KEM_CIPHERTEXT *ciphertext = NULL;
    TPM2B_SHARED_SECRET  *enc_secret = NULL;
    TPM2B_SHARED_SECRET  *ossl_dec_secret = NULL;

    r = test_ossl_mlkem_keygen(TPM2_MLKEM_PARMS_1024, &ossl_keypair);
    goto_if_error(r, "Error: OpenSSL ML-KEM key generation", error);

    r = test_get_mlkem_tpm2b_public_from_evp(ossl_keypair, &inPublic);
    goto_if_error(r, "Error: Convert OpenSSL ML-KEM public key", error);

    r = Esys_LoadExternal(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, &inPublic,
                          TPM2_RH_OWNER, &loaded_handle);
    goto_if_error(r, "Error: LoadExternal (ML-KEM public key)", error);

    r = Esys_Encapsulate(esys_context, loaded_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                         &ciphertext, &enc_secret);
    goto_if_error(r, "Error: Encapsulate (loaded external ML-KEM pub)", error);

    r = test_ossl_mlkem_decapsulate(ossl_keypair, ciphertext, &ossl_dec_secret);
    goto_if_error(r, "Error: OpenSSL decapsulate", error);

    if (enc_secret->size != ossl_dec_secret->size
        || memcmp(enc_secret->buffer, ossl_dec_secret->buffer, enc_secret->size) != 0) {
        LOG_ERROR("KEM interop FAILED: TPM encapsulate secret != OpenSSL decapsulate secret.");
        goto error;
    }

    r = Esys_FlushContext(esys_context, loaded_handle);
    goto_if_error(r, "Error: FlushContext (loaded external key)", error);
    loaded_handle = ESYS_TR_NONE;

    EVP_PKEY_free(ossl_keypair);
    Esys_Free(ciphertext);
    Esys_Free(enc_secret);
    free(ossl_dec_secret);
    return EXIT_SUCCESS;

error:
    if (loaded_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, loaded_handle) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup loaded_handle failed.");
    }
    EVP_PKEY_free(ossl_keypair);
    Esys_Free(ciphertext);
    Esys_Free(enc_secret);
    free(ossl_dec_secret);
    return EXIT_FAILURE;
#endif
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
#ifndef ENABLE_PQC
    UNUSED(esys_context);
    LOG_WARNING("Skipping: PQC not enabled (configure --enable-pqc)");
    return EXIT_SKIP;
#else
    int ret = test_esys_pqc_kem(esys_context);
    if (ret != EXIT_SUCCESS)
        return ret;
    return test_esys_pqc_kem_load_external_ossl_key(esys_context);
#endif
}
