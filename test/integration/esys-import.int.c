/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"
#include "tss2_mu.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the ESAPI commands Duplicate and Import.
 * We start by creating a primary key (Esys_CreatePrimary).
 * This primary key will be used as parent key for the Duplicate
 * command. A second primary key will be the parent key of the
 * duplicated key. In the last step the key is imported with the
 * first primary key as parent key (Esys_Import).
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    /*
     * Firth the policy value to be able to use Esys_Duplicate for an object has to be
     * determined with a policy trial session.
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

    r = Esys_PolicyAuthValue(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE
                             );
    goto_if_error(r, "Error: PolicyAuthValue", error);

    r = Esys_PolicyCommandCode(esys_context,
                               sessionTrial,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               TPM2_CC_Duplicate
                               );
    goto_if_error(r, "Error: PolicyCommandCode", error);

    TPM2B_DIGEST *policyDigestTrial;
    r = Esys_PolicyGetDigest(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &policyDigestTrial
                             );
    goto_if_error(r, "Error: PolicyGetDigest", error);

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0 },
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_NULL
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
    ESYS_TR primaryHandle_handle2;
    RSRC_NODE_T *primaryHandle_node;
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

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle_handle2,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esys create primary", error);

    r = esys_GetResourceObject(esys_context, primaryHandle_handle,
                               &primaryHandle_node);
    goto_if_error(r, "Error Esys GetResourceObject", error);

    LOG_INFO("Created Primary with handle 0x%08x...",
             primaryHandle_node->rsrc.handle);

    r = Esys_TR_SetAuth(esys_context, primaryHandle_handle, &authValuePrimary);
    goto_if_error(r, "Error: TR_SetAuth", error);

    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 11}
    };

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 1,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
             },
            .data = {
                 .size = 0,
                 .buffer = {}
             }
        }
    };

    inSensitive2.sensitive.userAuth = authKey2;

    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),

            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB
                 },
                 .scheme = {
                      .scheme =
                      TPM2_ALG_NULL,
                  },
                 .keyBits = 2048,
                 .exponent = 65537
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {}
                 ,
             }
        }
    };

    TPM2B_DATA outsideInfo2 = {
        .size = 0,
        .buffer = {}
        ,
    };

    TPML_PCR_SELECTION creationPCR2 = {
        .count = 0,
    };

    TPM2B_PUBLIC *outPublic2;
    TPM2B_PRIVATE *outPrivate2;
    TPM2B_CREATION_DATA *creationData2;
    TPM2B_DIGEST *creationHash2;
    TPMT_TK_CREATION *creationTicket2;

    inPublic2.publicArea.authPolicy = *policyDigestTrial;

    r = Esys_Create(esys_context,
                    primaryHandle_handle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive2,
                    &inPublic2,
                    &outsideInfo2,
                    &creationPCR2,
                    &outPrivate2,
                    &outPublic2,
                    &creationData2, &creationHash2, &creationTicket2);
    goto_if_error(r, "Error esys create ", error);

    LOG_INFO("\nSecond key created.");

    ESYS_TR loadedKeyHandle;

    r = Esys_Load(esys_context,
                  primaryHandle_handle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);
    goto_if_error(r, "Error esys load ", error);

    LOG_INFO("\nSecond Key loaded.");

    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    TPM2B_PUBLIC *keyPublic;
    TPM2B_NAME *keyName;
    TPM2B_NAME *keyQualifiedName;

    r = Esys_ReadPublic(esys_context,
                        loadedKeyHandle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &keyPublic,
                        &keyName,
                        &keyQualifiedName);

    goto_if_error(r, "Error esys ReadPublic", error);

    ESYS_TR policySession;
    TPMT_SYM_DEF policySymmetric = {.algorithm = TPM2_ALG_AES,
                                    .keyBits = {.aes = 128},
                                    .mode = {.aes = TPM2_ALG_CFB}
    };
    TPM2B_NONCE policyNonceCaller = {
        .size = 20,
        .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                   21, 22, 23, 24, 25, 26, 27, 28, 29, 30}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &policyNonceCaller,
                              TPM2_SE_POLICY, &policySymmetric, TPM2_ALG_SHA1,
                              &policySession);
    goto_if_error(r, "Error: During initialization of policy trial session", error);


    r = Esys_PolicyAuthValue(esys_context,
                             policySession,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE
                             );
    goto_if_error(r, "Error: PolicyAuthValue", error);

    r = Esys_PolicyCommandCode(esys_context,
                               policySession,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               TPM2_CC_Duplicate
                               );
    goto_if_error(r, "Error: PolicyCommandCode", error);

    TPM2B_DATA encryptionKey = {0};

    TPMT_SYM_DEF_OBJECT symmetric = {.algorithm = TPM2_ALG_NULL,
                                     .keyBits = {.aes = 128},
                                     .mode = {.aes = TPM2_ALG_CFB}};

    TPM2B_DATA *encryptionKeyOut;
    TPM2B_PRIVATE *duplicate;
    TPM2B_ENCRYPTED_SECRET *outSymSeed;

    r = Esys_Duplicate(
        esys_context,
        loadedKeyHandle,
        primaryHandle_handle2,
        policySession,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &encryptionKey,
        &symmetric,
        &encryptionKeyOut,
        &duplicate,
        &outSymSeed);

    goto_if_error(r, "Error: Duplicate", error);

    TPM2B_NAME *nameKeySign;
    TPM2B_PRIVATE *outPrivate;

    r = Esys_ReadPublic(esys_context,
                        loadedKeyHandle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &outPublic,
                        &nameKeySign,
                        &keyQualifiedName);
    goto_if_error(r, "Error: ReadPublic", error);

    r = Esys_Import(
        esys_context,
        primaryHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        encryptionKeyOut,
        outPublic,
        duplicate,
        outSymSeed,
        &symmetric,
        &outPrivate);
    goto_if_error(r, "Error: Import", error);

    r = Esys_FlushContext(esys_context, primaryHandle_handle);
    goto_if_error(r, "Flushing context", error);

    r = Esys_FlushContext(esys_context, primaryHandle_handle2);
    goto_if_error(r, "Flushing context", error);

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Flushing context", error);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}
