/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
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

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the function Esys_MakeCredential
 * We start by creating a primary key (Esys_CreatePrimary).
 * Based in the primary a second key will be created.
 * The public part of the key will be loaded by the function
 * Esys_LoadExternal. A credential will be encrypted with this
 * key with the command Esys_MakeCredential. The credential
 * will be activated with Esys_ActivateCredential.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

#ifdef TEST_SESSION
    ESYS_TR session;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE *nonceTpm;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    memset(&sessionAttributes, 0, sizeof sessionAttributes);

    RSRC_NODE_T *session_node;

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1, &session,
                              &nonceTpm);

    goto_if_error(r, "Error: During initialization of session", error);


    r = esys_GetResourceObject(esys_context, session,
                               &session_node);
    goto_if_error(r, "Error Esys GetResourceObject", error);

    LOG_INFO("Created session with handle 0x%08x...",
             session_node->rsrc.handle);

    ESYS_TR session2;
    RSRC_NODE_T *session2_node;

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1, &session2,
                              &nonceTpm);

    goto_if_error(r, "Error: During initialization of session", error);

    r = esys_GetResourceObject(esys_context, session2,
                               &session2_node);
    goto_if_error(r, "Error Esys GetResourceObject", error);

    LOG_INFO("Created session2 with handle 0x%08x...",
             session2_node->rsrc.handle);

#endif /* TEST_SESSION */

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
            .nameAlg = TPM2_ALG_SHA256,
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
    RSRC_NODE_T *primaryHandle_node;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle_handle,
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
            .nameAlg = TPM2_ALG_SHA256,
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

    r = Esys_LoadExternal(esys_context,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          NULL,
                          outPublic2,
                          TPM2_RH_OWNER,
                          &loadedKeyHandle);
    goto_if_error(r, "Error esys load exernal", error);

    TPM2B_PUBLIC *primaryKeyPublic;
    TPM2B_NAME *primaryKeyName;
    TPM2B_NAME *primaryKeyQualifiedName;

    r = Esys_ReadPublic(esys_context,
                        primaryHandle_handle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &primaryKeyPublic,
                        &primaryKeyName,
                        &primaryKeyQualifiedName);

    goto_if_error(r, "Error esys read public", error);

    TPM2B_DIGEST credential = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}};

    TPM2B_ID_OBJECT                *credentialBlob;
    TPM2B_ENCRYPTED_SECRET         *secret;

    r = Esys_MakeCredential(esys_context,
                            loadedKeyHandle,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &credential,
                            primaryKeyName,
                            &credentialBlob,
                            &secret
                            );
    goto_if_error(r, "Error: MakeCredential", error);

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error esys flush context", error);

    TPM2B_DIGEST *certInfo;

    r = Esys_Load(esys_context,
                  primaryHandle_handle,
#ifdef TEST_SESSION
                  session,
#else
                  ESYS_TR_PASSWORD,
#endif
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);
    goto_if_error(r, "Error esys load ", error);

    LOG_INFO("\nSecond Key loaded.");

    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    goto_if_error(r, "Error: TR_SetAuth", error);

    r = Esys_ActivateCredential(esys_context,
                                primaryHandle_handle,
                                loadedKeyHandle,

#ifdef TEST_SESSION
                                session,
#else
                                ESYS_TR_PASSWORD,
#endif
#ifdef TEST_SESSION
                                session2,
#else
                                ESYS_TR_PASSWORD,
#endif
                                ESYS_TR_NONE,
                                credentialBlob,
                                secret,
                                &certInfo
                                );
    goto_if_error(r, "Error: ActivateCredential", error);

    r = Esys_FlushContext(esys_context, primaryHandle_handle);
    goto_if_error(r, "Error during FlushContext", error);

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error esys flush context", error);

    return 0;

 error:
    return 1;
}
