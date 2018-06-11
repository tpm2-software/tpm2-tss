/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"
#include "tss2_mu.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the ESAPI policy commands related to
 * signed authorization actions.
 * Esys_PolicySigned, Esys_PolicyTicket, and Esys_PolicySecret.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

    /*
     * 1. Create Primary. This primary will be used as signing key.
     */

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = authValuePrimary,
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT  |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_RSAPSS,
                      .details = {
                          .rsapss = { .hashAlg = TPM2_ALG_SHA1 }
                      }
                  },
                 .keyBits = 2048,
                 .exponent = 65537,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };
    LOG_INFO("\nRSA key will be created.");

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    ESYS_TR primaryHandle_handle;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle_handle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esys create primary", error);

    TPM2B_NAME *nameKeySign;
    TPM2B_NAME *keyQualifiedName;

    r = Esys_ReadPublic(esys_context,
                        primaryHandle_handle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &outPublic,
                        &nameKeySign,
                        &keyQualifiedName);
    goto_if_error(r, "Error: ReadPublic", error);

    /*
     * 2. The policy expiration in 3600 seconds will be signed.
     *    Other possible restrictions policyRef, nonceTPM, and cpHashA
     *    will not be used.
     */
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}
    };
    TPMT_SIGNATURE *signature;

    /* Policy expiration -3600 (sha1sum 0xfffff1f0) will be signed */
    TPM2B_DIGEST signed_digest = {
        .size = 20,
        .buffer = { 0x9b, 0x8c, 0x05, 0x41, 0xb1, 0x56, 0x6e, 0xf3, 0xc6, 0xba,
                    0xae, 0xc9, 0xe4, 0x77, 0x39, 0x88, 0x68, 0x18, 0x20, 0x18 }
    };

    r = Esys_Sign(
        esys_context,
        primaryHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &signed_digest,
        &inScheme,
        &hash_validation,
        &signature);
    goto_if_error(r, "Error: Sign", error);

    /*
     * 3. A policy session will be created. Based on the signed policy the
     *    ticket policySignedTicket will be created.
     *    With this ticket the function Esys_PolicyTicket will be tested.
     */
    ESYS_TR session;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                   21, 22, 23, 24, 25, 26, 27, 28, 29, 30}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA1,
                              &session);
    goto_if_error(r, "Error: During initialization of policy trial session", error);

    TPM2B_NONCE policyRef = {0};
    TPM2B_NONCE nonceTPM = {0};
    TPM2B_DIGEST cpHashA = {0};
    INT32 expiration = -3600;
    TPM2B_TIMEOUT *timeout;
    TPMT_TK_AUTH *policySignedTicket;


    r = Esys_PolicySigned(
        esys_context,
        primaryHandle_handle,
        session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nonceTPM,
        &cpHashA,
        &policyRef,
        expiration,
        signature,
        &timeout,
        &policySignedTicket);
    goto_if_error(r, "Error: PolicySigned", error);

    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error: FlushContext", error);



    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA1,
                              &session);
    goto_if_error(r, "Error: During initialization of policy session", error);

    r = Esys_PolicyTicket(
        esys_context,
        session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        timeout,
        &cpHashA,
        &policyRef,
        nameKeySign,
        policySignedTicket);
    goto_if_error(r, "Error: PolicyTicket", error);

    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error: FlushContext", error);

    /*
     * 3. A policy tial session will be created. With this trial policy the
     *    function Esys_PolicySecret will be tested.
     */
    ESYS_TR sessionTrial;
    TPMT_SYM_DEF symmetricTrial = {.algorithm = TPM2_ALG_AES,
                                   .keyBits = {.aes = 128},
                                   .mode = {.aes = TPM2_ALG_CFB}
    };
    TPM2B_NONCE nonceCallerTrial = {
        .size = 20,
        .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                   21, 22, 23, 24, 25, 26, 27, 28, 29, 30}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session", error);

    TPMT_TK_AUTH *policySecretTicket;

    r = Esys_PolicySecret(
        esys_context,
        primaryHandle_handle,
        sessionTrial,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nonceTPM,
        &cpHashA,
        &policyRef,
        expiration,
        &timeout,
        &policySecretTicket);
    goto_if_error(r, "Error: PolicySecret", error);

    r = Esys_FlushContext(esys_context, sessionTrial);
    goto_if_error(r, "Error: FlushContext", error);

    r = Esys_FlushContext(esys_context, primaryHandle_handle);
    goto_if_error(r, "Error: FlushContext", error);

    return 0;

 error:
    return 1;
}
