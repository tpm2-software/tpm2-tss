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
#include <string.h> // for memcpy, strlen

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "tss2_common.h"     // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_esys.h"       // for Esys_Free, ESYS_TR_NONE, ESYS_TR_PASSWORD
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPMA_OBJECT_*, TPM2_ALG_*

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR

/* ---- Compute FIPS 204 µ (mu) for external-mu SignDigest --------------- */

/*
 * Compute the 64-byte µ value for ML-DSA external-mu signing:
 *
 *   tr = SHAKE256(pk, 64)
 *   µ  = SHAKE256(tr || 0x00 || len(ctx) || ctx || message, 64)
 *
 * Returns TSS2_RC_SUCCESS on success.
 */
static TSS2_RC
test_compute_mldsa_mu(const uint8_t *pk, size_t pk_len,
                      const uint8_t *ctx_str, size_t ctx_len,
                      const uint8_t *message, size_t msg_len,
                      uint8_t mu_out[64])
{
    TSS2_RC     r = TSS2_RC_SUCCESS;
    EVP_MD_CTX *md_ctx = NULL;
    uint8_t     tr[64];

    md_ctx = EVP_MD_CTX_new();
    goto_if_null(md_ctx, "Out of memory", TSS2_ESYS_RC_MEMORY, error_cleanup);

    /* Step 1: tr = SHAKE256(pk, 64) */
    if (EVP_DigestInit_ex(md_ctx, EVP_shake256(), NULL) != 1
        || EVP_DigestUpdate(md_ctx, pk, pk_len) != 1
        || EVP_DigestFinalXOF(md_ctx, tr, 64) != 1) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "SHAKE256(pk) failed", error_cleanup);
    }

    /* Step 2: µ = SHAKE256(tr || 0x00 || len(ctx) || ctx || message, 64) */
    EVP_MD_CTX_reset(md_ctx);

    if (EVP_DigestInit_ex(md_ctx, EVP_shake256(), NULL) != 1
        || EVP_DigestUpdate(md_ctx, tr, 64) != 1) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "SHAKE256 init failed", error_cleanup);
    }

    {
        uint8_t zero = 0x00;          /* pure ML-DSA, not pre-hash */
        uint8_t ctx_len_byte = (uint8_t)ctx_len;

        if (EVP_DigestUpdate(md_ctx, &zero, 1) != 1
            || EVP_DigestUpdate(md_ctx, &ctx_len_byte, 1) != 1) {
            goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "SHAKE256 update failed", error_cleanup);
        }
    }

    if (ctx_len > 0 && EVP_DigestUpdate(md_ctx, ctx_str, ctx_len) != 1) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "SHAKE256 ctx update failed", error_cleanup);
    }

    if (EVP_DigestUpdate(md_ctx, message, msg_len) != 1
        || EVP_DigestFinalXOF(md_ctx, mu_out, 64) != 1) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "SHAKE256 finalize failed", error_cleanup);
    }

error_cleanup:
    EVP_MD_CTX_free(md_ctx);
    return r;
}

/* ---- OpenSSL ML-DSA verification -------------------------------------- */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

#define OSSL_ALG_MLDSA_44 LN_ML_DSA_44
#define OSSL_ALG_MLDSA_65 LN_ML_DSA_65
#define OSSL_ALG_MLDSA_87 LN_ML_DSA_87

static const char *
test_mldsa_parms_to_ossl_name(TPMI_MLDSA_PARMS parameterSet) {
    switch (parameterSet) {
    case TPM2_MLDSA_PARMS_44: return OSSL_ALG_MLDSA_44;
    case TPM2_MLDSA_PARMS_65: return OSSL_ALG_MLDSA_65;
    case TPM2_MLDSA_PARMS_87: return OSSL_ALG_MLDSA_87;
    default:                  return NULL;
    }
}

static TSS2_RC
test_ossl_mldsa_pub_from_tpm(const TPM2B_PUBLIC *tpmPublicKey, EVP_PKEY **evpPublicKey) {
    TSS2_RC         r = TSS2_RC_SUCCESS;
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM     *params = NULL;
    EVP_PKEY_CTX   *ctx = NULL;
    const char     *alg_name = NULL;

    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(evpPublicKey, "evpPublicKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    alg_name = test_mldsa_parms_to_ossl_name(
        tpmPublicKey->publicArea.parameters.mldsaDetail.parameterSet);
    if (!alg_name) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE, "Unknown ML-DSA parameter set", error_cleanup);
    }

    build = OSSL_PARAM_BLD_new();
    goto_if_null(build, "Out of memory", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (!OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY,
                                          tpmPublicKey->publicArea.unique.mldsa.buffer,
                                          tpmPublicKey->publicArea.unique.mldsa.size)) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create ML-DSA key parameters",
                   error_cleanup);
    }

    params = OSSL_PARAM_BLD_to_param(build);
    goto_if_null(params, "Create ML-DSA key parameters", TSS2_ESYS_RC_GENERAL_FAILURE,
                 error_cleanup);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    goto_if_null(ctx, "Create ML-DSA EVP_PKEY_CTX", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, evpPublicKey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create ML-DSA EVP_PKEY", error_cleanup);
    }

error_cleanup:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
    return r;
}

/*
 * Verify an ML-DSA signature using OpenSSL EVP_DigestVerify.
 * The context string is passed via OSSL_SIGNATURE_PARAM_CONTEXT_STRING.
 */
static TSS2_RC
test_ossl_mldsa_verify_with_ctx(const TPM2B_PUBLIC   *tpmPublicKey,
                                const uint8_t        *ctx_str,
                                size_t                ctx_len,
                                const uint8_t        *message,
                                size_t                msg_len,
                                const TPMT_SIGNATURE *signature) {
    TSS2_RC       r = TSS2_RC_SUCCESS;
    EVP_PKEY     *publicKey = NULL;
    EVP_MD_CTX   *mdCtx = NULL;
    EVP_PKEY_CTX *pkCtx = NULL;

    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(message, "message is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    if (signature->sigAlg != TPM2_ALG_MLDSA) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "Expected TPM2_ALG_MLDSA signature");
    }

    r = test_ossl_mldsa_pub_from_tpm(tpmPublicKey, &publicKey);
    goto_if_error(r, "Convert ML-DSA public key for OpenSSL", error_cleanup);

    mdCtx = EVP_MD_CTX_new();
    goto_if_null(mdCtx, "Out of memory", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (EVP_DigestVerifyInit_ex(mdCtx, &pkCtx, NULL, NULL, NULL, publicKey, NULL) <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "EVP_DigestVerifyInit_ex failed",
                   error_cleanup);
    }

    if (ctx_len > 0) {
        OSSL_PARAM ctx_params[2];
        ctx_params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)ctx_str, ctx_len);
        ctx_params[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(pkCtx, ctx_params) <= 0) {
            goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Set context string failed",
                       error_cleanup);
        }
    }

    if (EVP_DigestVerify(mdCtx, signature->signature.mldsa.buffer,
                         signature->signature.mldsa.size, message, msg_len) != 1) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "OpenSSL ML-DSA verification failed", error_cleanup);
    }

error_cleanup:
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(publicKey);
    return r;
}
#endif

/** Test ML-DSA SignDigest / VerifyDigestSignature.
 *
 * An ML-DSA-65 primary key is created with allowExternalMu = 1.
 * The caller computes the 64-byte µ (mu) per FIPS 204:
 *
 *   tr = SHAKE256(pk, 64)
 *   µ  = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)
 *
 * The µ is signed via Esys_SignDigest and verified via
 * Esys_VerifyDigestSignature, then cross-verified with OpenSSL.
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_SignDigest() (M)
 *  - Esys_VerifyDigestSignature() (M)
 *  - Esys_FlushContext() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_pqc_signdigest(ESYS_CONTEXT *esys_context) {
    TSS2_RC r;

    ESYS_TR mldsa_handle = ESYS_TR_NONE;

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPMT_SIGNATURE   *signature = NULL;
    TPMT_TK_VERIFIED *validation = NULL;

    TPM2B_AUTH keyAuth = { .size = 5, .buffer = { 1, 2, 3, 4, 5 } };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0, .buffer = {0} },
            .data     = { .size = 0, .buffer = {0} },
        },
    };
    inSensitive.sensitive.userAuth = keyAuth;

    TPM2B_DATA         outsideInfo = { .size = 0, .buffer = {} };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type    = TPM2_ALG_MLDSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                  TPMA_OBJECT_SIGN_ENCRYPT |
                                  TPMA_OBJECT_FIXEDTPM |
                                  TPMA_OBJECT_FIXEDPARENT |
                                  TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = { .size = 0 },
            .parameters.mldsaDetail = {
                .parameterSet    = TPM2_MLDSA_PARMS_65,
                .allowExternalMu = 1,
            },
            .unique.mldsa = { .size = 0, .buffer = {} },
        },
    };

    const char    *message = "Hello, ML-DSA SignDigest!";
    const char    *ctx_str = "test";
    uint8_t        mu[64];
    TPM2B_DIGEST   mu_digest = { .size = 64 };

    TPM2B_SIGNATURE_CTX sig_ctx = { .size = 0 };

    TPMT_TK_HASHCHECK hashcheck = {
        .tag       = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest    = { .size = 0 },
    };

    /* ---- Create ML-DSA-65 primary (allowExternalMu = 1) --------------- */
    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER,
                        &(TPM2B_AUTH){ .size = 0, .buffer = {} });
    goto_if_error(r, "Error: TR_SetAuth (owner)", error);

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &mldsa_handle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error: CreatePrimary (ML-DSA-65, allowExternalMu=1)", error);

    r = Esys_TR_SetAuth(esys_context, mldsa_handle, &keyAuth);
    goto_if_error(r, "Error: TR_SetAuth (ML-DSA key)", error);

    /* ---- Compute µ (mu) ----------------------------------------------- */
    r = test_compute_mldsa_mu(
            outPublic->publicArea.unique.mldsa.buffer,
            outPublic->publicArea.unique.mldsa.size,
            (const uint8_t *)ctx_str, strlen(ctx_str),
            (const uint8_t *)message, strlen(message),
            mu);
    goto_if_error(r, "Error: compute µ (mu)", error);

    memcpy(mu_digest.buffer, mu, 64);

    /* Set up the context string for SignDigest / VerifyDigestSignature */
    sig_ctx.size = (UINT16)strlen(ctx_str);
    memcpy(sig_ctx.buffer, ctx_str, sig_ctx.size);

    /* ---- SignDigest --------------------------------------------------- */
    r = Esys_SignDigest(esys_context, mldsa_handle,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &sig_ctx, &mu_digest, &hashcheck,
                        &signature);
    goto_if_error(r, "Error: SignDigest", error);

    /* ---- VerifyDigestSignature ---------------------------------------- */
    r = Esys_VerifyDigestSignature(esys_context, mldsa_handle,
                                   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &sig_ctx, &mu_digest, signature,
                                   &validation);
    goto_if_error(r, "Error: VerifyDigestSignature", error);

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    /* ---- OpenSSL cross-verification ----------------------------------- */
    r = test_ossl_mldsa_verify_with_ctx(
            outPublic,
            (const uint8_t *)ctx_str, strlen(ctx_str),
            (const uint8_t *)message, strlen(message),
            signature);
    goto_if_error(r, "Error: OpenSSL ML-DSA cross-verification", error);
#endif

    /* ---- Cleanup ------------------------------------------------------ */
    r = Esys_FlushContext(esys_context, mldsa_handle);
    goto_if_error(r, "Error: FlushContext (ML-DSA)", error);
    mldsa_handle = ESYS_TR_NONE;

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(signature);
    Esys_Free(validation);
    return EXIT_SUCCESS;

error:
    if (mldsa_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, mldsa_handle) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup mldsa_handle failed.");
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(signature);
    Esys_Free(validation);
    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_pqc_signdigest(esys_context);
}
