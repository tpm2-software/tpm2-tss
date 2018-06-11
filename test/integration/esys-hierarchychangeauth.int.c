/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test then change of an authorization value of
 * a hierarchy.
 * To check whether the change was successful a primary key is created
 * with the handle of this hierarchy and the new authorization.
 * Also second primary is created after a call of Esys_TR_SetAuth with
 * the new auth value.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;
    ESYS_TR authHandle_handle = ESYS_TR_RH_OWNER;
    TPM2B_AUTH newAuth = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_AUTH emptyAuth = {
        .size = 0,
        .buffer = {}
    };

    r = Esys_HierarchyChangeAuth(esys_context,
                                 authHandle_handle,
                                 ESYS_TR_PASSWORD,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 &newAuth);
    goto_if_error(r, "Error: HierarchyChangeAuth", error);

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

    goto_if_error(r, "Error: TR_SetAuth", error);

    ESYS_TR primaryHandle_handle;
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

    r = Esys_FlushContext(esys_context, primaryHandle_handle);
    goto_if_error(r, "Flushing context", error);

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &newAuth);
    goto_if_error(r, "Error SetAuth", error);

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle_handle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esys create primary", error);

    r = Esys_FlushContext(esys_context, primaryHandle_handle);
    goto_if_error(r, "Flushing context", error);

    r = Esys_HierarchyChangeAuth(esys_context,
                                 authHandle_handle,
                                 ESYS_TR_PASSWORD,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 &emptyAuth);
    goto_if_error(r, "Error: HierarchyChangeAuth", error);

    return 0;

error:
    return 1;
}
