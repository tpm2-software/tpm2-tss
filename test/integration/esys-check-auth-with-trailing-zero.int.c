/* SPDX-FileCopyrightText: 2023, Juergen Repp */
/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for NULL, EXIT_FAILURE, EXIT_SUCCESS

#include "tss2_common.h"      // for TSS2_RC_SUCCESS, TSS2_RC, UINT16
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_Free, Esys_FlushContext
#include "tss2_tpm2_types.h"  // for TPM2_ALG_SHA256, TPM2B_PUBLIC, TPM2B_AUTH

#define LOGMODULE test
#include "util/log.h"         // for goto_if_error, LOG_ERROR

/** This test is intended to test trailing zeros in an auth value
 *
 * An primary key with an auth value with trailing zeros is created.
 * A key with this primary is parent is created.
 * Esys_TR_SetAuth which strips the zeros is calles.
 * The key is created again.
 * The creation of an session where an bind key with a trailing
 * zero in the auth value is tested.
 * A session where the owner hierarchy is used as bind key in
 * combination with Esys_HierarchyChangeAuth is tested.
 * An nv index with trailing zeros in the auth value with
 * trailing zeros in combination with Esys_NV_ChangeAuth
 * is tested.
 *
 * Tested ESYS commands:
 *  - Esys_Create() (M)
 *  - Esys_CreatePrimary() (M)
 *  - Esys_FlushContext() (M)
 *  - Esys_StartAuthSession() (M)
 *  - Esys_PolicyAuthValue() (M)
 *  - Esys_PolicyCommandcode() (M)
 *  - Esys_PolicyGetDigest() (M)
 *  - Esys_NV_DefineSpace() (M)
 *  - Esys_NV_Write() (M)
 *  - Esys_NV_Read() (M)
 *  - Esys_NV_UndefineSpace() (M)
 *  - Esys_NV_ChangeAuth() (M)

 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

int
test_esys_trailing_zeros_in_auth(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    ESYS_TR enc_session = ESYS_TR_NONE;
    ESYS_TR bind_key = ESYS_TR_NONE;
    ESYS_TR key = ESYS_TR_NONE;
    ESYS_TR key_sign = ESYS_TR_NONE;
    ESYS_TR policySession = ESYS_TR_NONE;
    ESYS_TR sessionTrial = ESYS_TR_NONE;
    ESYS_TR nvHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TPM2B_PUBLIC *outPublicEcc = NULL;
    TPM2B_CREATION_DATA *creationDataEcc = NULL;
    TPM2B_DIGEST *creationHashEcc = NULL;
    TPMT_TK_CREATION *creationTicketEcc = NULL;

    TPM2B_PUBLIC *outPublic2 = NULL;
    TPM2B_PRIVATE *outPrivate2 = NULL;
    TPM2B_CREATION_DATA *creationData2 = NULL;
    TPM2B_DIGEST *creationHash2 = NULL;
    TPMT_TK_CREATION *creationTicket2 = NULL;

    TPM2B_PUBLIC *outPublic3 = NULL;
    TPM2B_PRIVATE *outPrivate3 = NULL;


    TPM2B_AUTH authValuePrimary = {
        .size = 6,
        .buffer = {1, 2, 3, 4, 5, 0}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
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

    TPM2B_PUBLIC inPublicPrimary = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
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
            .parameters.eccDetail = {
                 .symmetric ={
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                            .scheme = TPM2_ALG_NULL
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {
                      .scheme = TPM2_ALG_NULL,
                      .details = {}}
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}},
             },
        },
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                           &inPublicPrimary,
                           &outsideInfo, &creationPCR, &primaryHandle,
                           &outPublicEcc, &creationDataEcc, &creationHashEcc,
                           &creationTicketEcc);
    goto_if_error(r, "Error esys create primary", error);

    TPMA_SESSION sessionAttributes;
    sessionAttributes = (TPMA_SESSION_DECRYPT |
                         TPMA_SESSION_ENCRYPT |
                         TPMA_SESSION_CONTINUESESSION);

    r = Esys_TR_SetAuth(esys_context, primaryHandle, &authValuePrimary);
    goto_if_error(r, "Error: TR_SetAuth", error);

    /* Test Session with bind key */

    static const TPMT_SYM_DEF SESSION_TEMPLATE_SYM_AES_128_CFB =
        {
         .algorithm = TPM2_ALG_AES,
         .keyBits.aes = 128,
         .mode.aes = TPM2_ALG_CFB,
        };

    TPM2B_PUBLIC template =
        {
         .size = sizeof(TPMT_PUBLIC),
         .publicArea = {
                        .type = TPM2_ALG_KEYEDHASH,
                        .nameAlg = TPM2_ALG_SHA256,
                        .parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL,
                        .unique.keyedHash.size = TPM2_SHA256_DIGEST_SIZE,
                        },
        };
    TPM2B_SENSITIVE_CREATE sensitive =
        {
         .size = sizeof(TPMS_SENSITIVE_CREATE),
         .sensitive.data.size = 1,
         .sensitive.data.buffer[0] = 1,
         .sensitive.userAuth.size = 4,
         .sensitive.userAuth.buffer = { 1, 2, 3, 0 },
        };

    r = Esys_Create(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                    ESYS_TR_NONE, &sensitive,  &template, NULL, &(TPML_PCR_SELECTION) {},
                    &outPrivate3 , &outPublic3, NULL, NULL, NULL);
    goto_if_error(r, "Error Esys_Create", error);

    r = Esys_Load(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  outPrivate3, outPublic3, &bind_key);
    goto_if_error(r, "Error Esys_Load", error);

    TPM2B_AUTH bind_key_auth =
        {
         .size = 4,
         .buffer = { 1, 2, 3, 0, },
        };

    r = Esys_TR_SetAuth(esys_context, bind_key, &bind_key_auth);
    goto_if_error(r, "Error Esys_TR_SetAuth", error);

    r = Esys_StartAuthSession(esys_context, primaryHandle, bind_key, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
                              &SESSION_TEMPLATE_SYM_AES_128_CFB,
                              TPM2_ALG_SHA256, &enc_session);
    goto_if_error(r, "Error Esys_StartAuthSession", error);

    r = Esys_TRSess_SetAttributes(esys_context, enc_session, sessionAttributes, 0xff);
    goto_if_error(r, "Error Esys_TRSess_SetAttributes", error);

    r = Esys_StartAuthSession(esys_context, primaryHandle, ESYS_TR_NONE,
                              enc_session, ESYS_TR_NONE,
                              ESYS_TR_NONE, NULL, TPM2_SE_POLICY,
                              &SESSION_TEMPLATE_SYM_AES_128_CFB,
                              TPM2_ALG_SHA256, &session);
    goto_if_error(r, "Error Esys_StartAuthSession", error);

    r = Esys_FlushContext(esys_context, enc_session);
    goto_if_error(r, "Error Esys_FlushContext", error);
    enc_session = ESYS_TR_NONE;

    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error Esys_FlushContext", error);
    enc_session = ESYS_TR_NONE;

    r = Esys_FlushContext(esys_context, bind_key);
    goto_if_error(r, "Error Esys_FlushContext", error);
    bind_key = ESYS_TR_NONE;

    /* Test HierarchyChangeAuth */

    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = { 6, 7, 8, 9, 10, 0 }
    };

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 0,
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


    TPM2B_AUTH newAuth = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 0 }
     };

    TPM2B_AUTH newAuth2 = {
        .size = 6,
        .buffer = {11, 12, 13, 14, 15, 0 }
    };

    TPM2B_PUBLIC template_parent = {
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
                 .exponent = 0
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {}
                 ,
             }
        }
    };

    Esys_Free(outPublic3);
    outPublic3 = NULL;
    Esys_Free(outPrivate3);
    outPrivate3 = NULL;

    r = Esys_Create(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                    ESYS_TR_NONE, &inSensitive2,  &template_parent, NULL, &(TPML_PCR_SELECTION) {},
                    &outPrivate3 , &outPublic3, NULL, NULL, NULL);
    goto_if_error(r, "Error Esys_Create", error);

    r = Esys_HierarchyChangeAuth(esys_context,
                                 ESYS_TR_RH_OWNER,
                                 ESYS_TR_PASSWORD,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 &newAuth);
    goto_if_error(r, "Error Esys_HierarchyChangeAuth", error);

    r = Esys_StartAuthSession(esys_context, primaryHandle, ESYS_TR_RH_OWNER, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
                              &SESSION_TEMPLATE_SYM_AES_128_CFB,
                              TPM2_ALG_SHA256, &session);
    goto_if_error(r, "Error Esys_StartAuthSession", error);

    r = Esys_TRSess_SetAttributes(esys_context, session, sessionAttributes, 0xff);
    goto_if_error(r, "Error Esys_TRSess_SetAttributes", error);

    r = Esys_Load(esys_context, primaryHandle, session, ESYS_TR_NONE, ESYS_TR_NONE,
                  outPrivate3, outPublic3, &key);
    goto_if_error(r, "Error Esys_Load", error);

    r = Esys_HierarchyChangeAuth(esys_context,
                                 ESYS_TR_RH_OWNER,
                                 ESYS_TR_PASSWORD,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 &newAuth2);
    goto_if_error(r, "Error: HierarchyChangeAuth", error);

    Esys_Free(outPublic3);
    Esys_Free(outPrivate3);

    TPM2B_PUBLIC template_sign = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
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
            .parameters.eccDetail = {
                 .symmetric ={
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                            .scheme = TPM2_ALG_NULL
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {
                      .scheme = TPM2_ALG_NULL,
                      .details = {}}
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}},
             },
        },
    };

    Esys_FlushContext(esys_context, primaryHandle);
    primaryHandle = ESYS_TR_NONE;

    r = Esys_TR_SetAuth(esys_context, key, &authKey2);
    goto_if_error(r, "Error Esys_", error);

    r = Esys_Create(esys_context, key, ESYS_TR_PASSWORD, session,
                    ESYS_TR_NONE, &inSensitive2,  &template_sign, NULL, &(TPML_PCR_SELECTION) {},
                    &outPrivate3 , &outPublic3, NULL, NULL, NULL);
    goto_if_error(r, "Error Esys_Create", error);

    r = Esys_Load(esys_context, key, session, ESYS_TR_NONE, ESYS_TR_NONE,
                  outPrivate3, outPublic3, &key_sign);
    goto_if_error(r, "Error Esys_Load", error);

    /* Reset auth value for storage hierarchy */
    r = Esys_HierarchyChangeAuth(esys_context,
                                 ESYS_TR_RH_OWNER,
                                 ESYS_TR_PASSWORD,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 NULL);
    goto_if_error(r, "Error: HierarchyChangeAuth", error);

    /* Test NV_ChangeAuth */

    TPM2B_NV_PUBLIC *nvPublic = NULL;
    TPM2B_NAME *nvName = NULL;
    TPM2B_MAX_NV_BUFFER *nv_test_data2 = NULL;
    TPM2B_DIGEST *policyDigestTrial = NULL;
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
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA256,
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
                               TPM2_CC_NV_ChangeAuth
                               );
    goto_if_error(r, "Error: PolicyCommandCode", error);

    r = Esys_PolicyGetDigest(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &policyDigestTrial
                             );
    goto_if_error(r, "Error: PolicyGetDigest", error);

    r = Esys_FlushContext(esys_context, sessionTrial);
    goto_if_error(r, "Flushing context", error);
    sessionTrial = ESYS_TR_NONE;

    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 0}};

    TPM2B_AUTH new_auth = {.size = 20,
                           .buffer={30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                                    40, 41, 42, 43, 44, 45, 46, 47, 48, 0}};

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_READ_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD
                ),
            .authPolicy = *policyDigestTrial,
            .dataSize = 32,
        }
    };

    Esys_Free(policyDigestTrial);
    policyDigestTrial = NULL;

    r = Esys_NV_DefineSpace(esys_context,
                            ESYS_TR_RH_OWNER,
                            session,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &auth,
                            &publicInfo,
                            &nvHandle);

    goto_if_error(r, "Error esys define nv space", error);

    UINT16 offset = 0;
    TPM2B_MAX_NV_BUFFER nv_test_data =
        { .size = 20,
          .buffer= {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0}};

    r = Esys_NV_Write(esys_context,
                      nvHandle,
                      nvHandle,
                      session,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      &nv_test_data,
                      offset);

    goto_if_error(r, "Error esys nv write", error);

    r = Esys_NV_Read(esys_context,
                     nvHandle,
                     nvHandle,
                     session,
                     ESYS_TR_NONE,
                     ESYS_TR_NONE,
                     20,
                     0,
                     &nv_test_data2);

    goto_if_error(r, "Error esys nv read", error);

    Esys_Free(nvPublic);
    Esys_Free(nvName);
    Esys_Free(nv_test_data2);
    nv_test_data2 = NULL;

    TPMT_SYM_DEF policySymmetric =
        {.algorithm = TPM2_ALG_AES,
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
                              TPM2_SE_POLICY, &policySymmetric, TPM2_ALG_SHA256,
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
                               TPM2_CC_NV_ChangeAuth
                               );
    goto_if_error(r, "Error: PolicyCommandCode", error);

    r = Esys_NV_ChangeAuth(esys_context, nvHandle, policySession,
                           ESYS_TR_NONE, ESYS_TR_NONE, &new_auth);
    goto_if_error(r, "Error Esys_NV_ChangeAuth", error);

    r = Esys_NV_Read(esys_context,
                     nvHandle,
                     nvHandle,
                     session,
                     ESYS_TR_NONE,
                     ESYS_TR_NONE,
                     20,
                     0,
                     &nv_test_data2);

    goto_if_error(r, "Error esys nv read", error);

    Esys_Free(nv_test_data2);
    nv_test_data2 = NULL;

    r = Esys_NV_UndefineSpace(esys_context,
                              ESYS_TR_RH_OWNER,
                              nvHandle,
                              session,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE);
    goto_if_error(r, "Error: NV_UndefineSpace", error);

    nvHandle = ESYS_TR_NONE;

 error:

    if (session != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, policySession) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup session failed.");
        }
    }

    if (session != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup session failed.");
        }
    }

    if (enc_session != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, enc_session) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup session failed.");
        }
    }

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    if (bind_key != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, bind_key) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    if (key != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, key) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup key.");
        }
     }

      if (key_sign != ESYS_TR_NONE) {
          if (Esys_FlushContext(esys_context, key_sign) != TSS2_RC_SUCCESS) {
              LOG_ERROR("Cleanup key2 failed.");
          }
      }

      if (nvHandle != ESYS_TR_NONE) {
          if (Esys_NV_UndefineSpace(esys_context,
                                    ESYS_TR_RH_OWNER,
                                    nvHandle,
                                    session,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE) != TSS2_RC_SUCCESS) {
              LOG_ERROR("Cleanup nvHandle failed.");
          }
    }

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(outPublicEcc);
    Esys_Free(creationDataEcc);
    Esys_Free(creationHashEcc);
    Esys_Free(creationTicketEcc);
    Esys_Free(outPublic2);
    Esys_Free(outPrivate2);
    Esys_Free(outPublic3);
    Esys_Free(outPrivate3);
    Esys_Free(creationData2);
    Esys_Free(creationHash2);
    Esys_Free(creationTicket2);

    if (r)
        return EXIT_FAILURE;
    else
        return EXIT_SUCCESS;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_trailing_zeros_in_auth(esys_context);
}
