/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
 *******************************************************************************/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2_esys.h>
#include "tss2-sys/sysapi_util.h"

#include "test.h"
#include "esys_types.h"
#include "esys_iutil.h"

#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the unseal operation for the ESAPI command
 * Unseal.
 * We start by creating a primary key (Esys_CreatePrimary).
 * Based on the primary key a second key with a password and the to be sealed
 * data defined in the sensitive area will be created (Esys_Create).
 * This key will be loaded and the unseal command (Esys_Unseal) will be used
 * to retrieve the sealed data.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{

    /*
     * 1. Create Primary
     */
    TSS2_RC r;

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
                           ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitivePrimary, &inPublic,
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

    /*
     * 2. Create second key with sealed data
     */

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
                .size = 8,
                .buffer = {3,2,3,2,3,2,3,2}
            }
        }
    };

    inSensitive2.sensitive.userAuth = authKey2;

    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            /* type = TPM2_ALG_RSA, */
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (
                TPMA_OBJECT_USERWITHAUTH |
                /* TPMA_OBJECT_RESTRICTED | */
                /* TPMA_OBJECT_DECRYPT | */
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT
                /* TPMA_OBJECT_SENSITIVEDATAORIGIN */
            ),

            .authPolicy = {
                .size = 0,
            },
            /*
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                },
                .keyBits = 2048,
                .exponent = 65537
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {}
                ,
            }
            */
            .parameters.keyedHashDetail = {
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {
                        .hmac = {
                            .hashAlg = TPM2_ALG_SHA256
                        }
                    }
                }
            },
            .unique.keyedHash = {
                .size = 0,
                .buffer = {},
            },
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

    /*
     * 3. Load second key
     */

    r = Esys_Load(esys_context,
                  primaryHandle_handle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);
    goto_if_error(r, "Error esys load ", error);

    LOG_INFO("\nSecond Key loaded.");

    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    /*
     * 4. Unseal key
     */

    TPM2B_SENSITIVE_DATA *outData;

    r = Esys_Unseal(esys_context, loadedKeyHandle, ESYS_TR_PASSWORD,
        ESYS_TR_NONE, ESYS_TR_NONE, &outData);
    goto_if_error(r, "Error esys Unseal ", error);

    if(memcmp(&(outData->buffer), &(inSensitive2.sensitive.data.buffer),
        inSensitive2.sensitive.data.size)!=0){
        LOG_ERROR("Error: Unsealed Data is unequal.");
        goto error;
    }

    LOG_INFO("\nData successfully unsealed.");

    /*
     * 5. Flush Context
     */

    r = Esys_FlushContext(esys_context, primaryHandle_handle);
    goto_if_error(r, "Error during FlushContext", error);

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error during FlushContext", error);

    return EXIT_SUCCESS;

    error:
    return EXIT_FAILURE;
}
