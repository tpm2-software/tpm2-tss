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
#include <string.h> // for memcpy

#include "test-esys.h" // for EXIT_SKIP

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "tss2_common.h"     // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_esys.h"       // for Esys_Free, ESYS_TR_NONE, ESYS_TR_PASSWORD
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPMA_OBJECT_*, TPM2_ALG_*

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
/* OpenSSL 3.5+ names from obj_mac.h */
#define OSSL_ALG_MLDSA_44 LN_ML_DSA_44
#define OSSL_ALG_MLDSA_65 LN_ML_DSA_65
#define OSSL_ALG_MLDSA_87 LN_ML_DSA_87

static const char *
test_mldsa_parms_to_ossl_name(TPMI_MLDSA_PARMS parameterSet) {
    switch (parameterSet) {
    case TPM2_MLDSA_PARMS_44:
        return OSSL_ALG_MLDSA_44;
    case TPM2_MLDSA_PARMS_65:
        return OSSL_ALG_MLDSA_65;
    case TPM2_MLDSA_PARMS_87:
        return OSSL_ALG_MLDSA_87;
    default:
        return NULL;
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
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "Create ML-DSA key parameters", error_cleanup);
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

static TSS2_RC
test_ossl_mldsa_verify(const TPM2B_PUBLIC   *tpmPublicKey,
                       const uint8_t        *message,
                       size_t                messageSize,
                       const TPMT_SIGNATURE *signature) {
    TSS2_RC     r = TSS2_RC_SUCCESS;
    EVP_PKEY   *publicKey = NULL;
    EVP_MD_CTX *mdCtx = NULL;

    return_if_null(tpmPublicKey, "tpmPublicKey is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(message, "message is NULL", TSS2_ESYS_RC_BAD_REFERENCE);
    return_if_null(signature, "signature is NULL", TSS2_ESYS_RC_BAD_REFERENCE);

    if (signature->sigAlg != TPM2_ALG_MLDSA) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "Expected TPM2_ALG_MLDSA signature");
    }

    r = test_ossl_mldsa_pub_from_tpm(tpmPublicKey, &publicKey);
    return_if_error(r, "Convert ML-DSA public key for OpenSSL");

    mdCtx = EVP_MD_CTX_new();
    goto_if_null(mdCtx, "Out of memory", TSS2_ESYS_RC_MEMORY, error_cleanup);

    if (EVP_DigestVerifyInit_ex(mdCtx, NULL, NULL, NULL, NULL, publicKey, NULL) <= 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "EVP_DigestVerifyInit_ex failed",
                   error_cleanup);
    }

    if (EVP_DigestVerify(mdCtx, signature->signature.mldsa.buffer, signature->signature.mldsa.size,
                         message, messageSize)
        != 1) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "OpenSSL ML-DSA verification failed",
                   error_cleanup);
    }

error_cleanup:
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(publicKey);
    return r;
}
#endif

/** Test the ML-DSA streaming sign / verify sequence.
 *
 * An ML-DSA-65 primary key is created under the owner hierarchy.  Data is
 * signed using the PQC streaming API:
 *   Esys_SignSequenceStart → Esys_SequenceUpdate (×1) → Esys_SignSequenceComplete
 *
 * The resulting signature is verified using:
 *   VerifySequenceStart → SequenceUpdate (×2) → VerifySequenceComplete
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_SignSequenceStart() (M)
 *  - Esys_SequenceUpdate() (M)
 *  - Esys_SignSequenceComplete() (M)
 *  - Esys_VerifySequenceStart() (M)
 *  - Esys_VerifySequenceComplete() (M)
 *  - Esys_FlushContext() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_pqc_sign(ESYS_CONTEXT *esys_context) {
    TSS2_RC r;

    ESYS_TR mldsa_handle = ESYS_TR_NONE;
    ESYS_TR sign_seq = ESYS_TR_NONE;
    ESYS_TR verify_seq = ESYS_TR_NONE;

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPMT_SIGNATURE   *signature = NULL;
    TPMT_TK_VERIFIED *validation = NULL;

    /* Auth values */
    TPM2B_AUTH keyAuth = { .size = 5, .buffer = { 1, 2, 3, 4, 5 } };
    TPM2B_AUTH seqAuth = { .size = 4, .buffer = { 9, 8, 7, 6 } };

    /* Application data split into two chunks */
    TPM2B_MAX_BUFFER data1
        = { .size = 10, .buffer = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 } };
    TPM2B_MAX_BUFFER data2
        = { .size = 10, .buffer = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13 } };

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
                .parameterSet = TPM2_MLDSA_PARMS_65,
            },
            .unique.mldsa = { .size = 0, .buffer = {} },
        },
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &(TPM2B_AUTH){ .size = 0, .buffer = {} });
    goto_if_error(r, "Error: TR_SetAuth (owner)", error);

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &mldsa_handle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error: CreatePrimary (ML-DSA-65)", error);

    r = Esys_TR_SetAuth(esys_context, mldsa_handle, &keyAuth);
    goto_if_error(r, "Error: TR_SetAuth (ML-DSA key)", error);

    /* NULL context means no pre-hash context string */
    r = Esys_SignSequenceStart(esys_context, mldsa_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                               ESYS_TR_NONE, &seqAuth, NULL /* context */, &sign_seq);
    goto_if_error(r, "Error: SignSequenceStart", error);

    r = Esys_TR_SetAuth(esys_context, sign_seq, &seqAuth);
    goto_if_error(r, "Error: TR_SetAuth (sign_seq)", error);

    r = Esys_SequenceUpdate(esys_context, sign_seq, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &data1);
    goto_if_error(r, "Error: SequenceUpdate (sign, data1)", error);

    /* SignSequenceComplete: sh1 = seqHandle auth, sh2 = keyHandle auth */
    r = Esys_SignSequenceComplete(esys_context, sign_seq, mldsa_handle, ESYS_TR_PASSWORD,
                                  ESYS_TR_PASSWORD, ESYS_TR_NONE, &data2, &signature);
    goto_if_error(r, "Error: SignSequenceComplete", error);
    sign_seq = ESYS_TR_NONE; /* consumed by Complete */

    r = Esys_VerifySequenceStart(esys_context, mldsa_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                 ESYS_TR_NONE, &seqAuth, NULL /* hint */, NULL /* context */,
                                 &verify_seq);
    goto_if_error(r, "Error: VerifySequenceStart", error);

    r = Esys_TR_SetAuth(esys_context, verify_seq, &seqAuth);
    goto_if_error(r, "Error: TR_SetAuth (verify_seq)", error);

    r = Esys_SequenceUpdate(esys_context, verify_seq, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &data1);
    goto_if_error(r, "Error: SequenceUpdate (verify, data1)", error);

    r = Esys_SequenceUpdate(esys_context, verify_seq, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &data2);
    goto_if_error(r, "Error: SequenceUpdate (verify, data2)", error);

    /* VerifySequenceComplete: sh1 = seqHandle auth, keyHandle has no auth */
    r = Esys_VerifySequenceComplete(esys_context, verify_seq, mldsa_handle, ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE, ESYS_TR_NONE, signature, &validation);
    goto_if_error(r, "Error: VerifySequenceComplete", error);
    verify_seq = ESYS_TR_NONE; /* consumed by Complete */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    {
        uint8_t verify_message[sizeof(data1.buffer) + sizeof(data2.buffer)] = { 0 };
        size_t  verify_message_size = data1.size + data2.size;

        memcpy(verify_message, data1.buffer, data1.size);
        memcpy(verify_message + data1.size, data2.buffer, data2.size);

        r = test_ossl_mldsa_verify(outPublic, verify_message, verify_message_size, signature);
        goto_if_error(r, "Error: OpenSSL ML-DSA verify", error);
    }
#endif

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
    if (sign_seq != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, sign_seq) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup sign_seq failed.");
    }
    if (verify_seq != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, verify_seq) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup verify_seq failed.");
    }
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
#ifndef ENABLE_PQC
    UNUSED(esys_context);
    LOG_WARNING("Skipping: PQC not enabled (configure --enable-pqc)");
    return EXIT_SKIP;
#else
    return test_esys_pqc_sign(esys_context);
#endif
}
