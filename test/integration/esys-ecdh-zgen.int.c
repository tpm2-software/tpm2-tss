/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test Esys_ECDH_ZGen.  based on an ECC key
 * created with Esys_CreatePrimary and a dummy ECC point.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r;
    ESYS_TR session;
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    memset(&sessionAttributes, 0, sizeof sessionAttributes);

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    goto_if_error(r, "Error: During initialization of session", error);

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };
    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB,
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_ECDH,
                      .details = {.ecdh = {.hashAlg = TPM2_ALG_SHA1}
                      }
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {.scheme = TPM2_ALG_NULL }
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}}
             }
            ,
        }
    };
    LOG_INFO("\nECC key will be created.");
    TPM2B_PUBLIC inPublic = inPublicECC;

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}
        ,
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

    ESYS_TR eccHandle;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublic,
                           &outsideInfo, &creationPCR, &eccHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esapi create primary", error);

    TPM2B_ECC_POINT inPoint= {
        .size = 0,
        .point = {
            .x = {
                 .size =  32,
                 .buffer = {
                     0x25, 0xdb, 0x1f, 0x8b, 0xbc, 0xfa, 0xbc, 0x31,
                     0xf8, 0x17, 0x6a, 0xcb, 0xb2, 0xf8, 0x40, 0xa3,
                     0xb6, 0xa5, 0xd3, 0x40, 0x65, 0x9d, 0x37, 0xee,
                     0xd9, 0xfd, 0x52, 0x47, 0xf5, 0x14, 0xd5, 0x98
                 },
             },
            .y = {
                 .size = 32,
                 .buffer = {
                     0xed, 0x62, 0x3e, 0x3d, 0xd2, 0x09, 0x08, 0xcf,
                     0x58, 0x3c, 0x81, 0x4b, 0xbf, 0x65, 0x7e, 0x08,
                     0xab, 0x9f, 0x40, 0xff, 0xea, 0x51, 0xda, 0x21,
                     0x29, 0x8c, 0xe2, 0x4d, 0xeb, 0x34, 0x4c, 0xcc
                 }
             }
        }
    };

    TPM2B_ECC_POINT *outPoint;
    r = Esys_ECDH_ZGen(
        esys_context,
        eccHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inPoint,
        &outPoint);
    goto_if_error(r, "Error: ECDH_ZGen", error);

    r = Esys_FlushContext(esys_context, eccHandle);
    goto_if_error(r, "Error during FlushContext", error);

    return 0;

 error:
    LOG_ERROR("\nError Code: %x\n", r);
    return 1;
}
