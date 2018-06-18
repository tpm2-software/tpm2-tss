/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#include "test-esapi.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the GetTime command with password
 * authentication.
 * We create a RSA primary signing key which will be used
 * for signing.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR signHandle = ESYS_TR_NONE;
    int failure_return = EXIT_FAILURE;

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0},
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
                .objectAttributes = (
                    TPMA_OBJECT_USERWITHAUTH |
                    TPMA_OBJECT_RESTRICTED |
                    TPMA_OBJECT_SIGN_ENCRYPT |
                    TPMA_OBJECT_FIXEDTPM |
                    TPMA_OBJECT_FIXEDPARENT |
                    TPMA_OBJECT_SENSITIVEDATAORIGIN
                    ),
                .authPolicy = {
                        .size = 0,
                    },
                .parameters.rsaDetail = {
                    .symmetric = {
                        .algorithm = TPM2_ALG_NULL,
                        .keyBits.aes = 128,
                        .mode.aes = TPM2_ALG_CFB,
                        },
                    .scheme = {
                         .scheme = TPM2_ALG_RSASSA,
                         .details = { .rsassa = { .hashAlg = TPM2_ALG_SHA1 }},

                    },
                    .keyBits = 2048,
                    .exponent = 0,
                },
                .unique.rsa = {
                        .size = 0,
                        .buffer = {},
                    },
            },
        };

    TPM2B_AUTH authValue = {
                .size = 0,
                .buffer = {}
    };


    TPM2B_DATA outsideInfo = {
            .size = 0,
            .buffer = {},
    };


    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    LOG_INFO("\nRSA key will be created.");

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    RSRC_NODE_T *primaryHandle_node;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                           &inPublic, &outsideInfo, &creationPCR,
                           &signHandle, &outPublic, &creationData,
                           &creationHash, &creationTicket);
    goto_if_error(r, "Error esys create primary", error);

    r = esys_GetResourceObject(esys_context, signHandle,
                               &primaryHandle_node);
    goto_if_error(r, "Error Esys GetResourceObject", error);

    LOG_INFO("Created Primary with handle 0x%08x...",
             primaryHandle_node->rsrc.handle);

    r = Esys_TR_SetAuth(esys_context, signHandle,
                        &authValuePrimary);
    goto_if_error(r, "Error: TR_SetAuth", error);

    ESYS_TR privacyAdminHandle= ESYS_TR_RH_ENDORSEMENT;
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    TPM2B_DATA qualifyingData = {0};
    TPM2B_ATTEST *timeInfo;
    TPMT_SIGNATURE *signature;

     r = Esys_GetTime (
         esys_context,
         privacyAdminHandle,
         signHandle,
         ESYS_TR_PASSWORD,
         ESYS_TR_PASSWORD,
         ESYS_TR_NONE,
         &qualifyingData,
         &inScheme,
         &timeInfo,
         &signature);
    if (r == TPM2_RC_COMMAND_CODE) {
        LOG_WARNING("Command TPM2_GetTime not supported by TPM.");
        r = Esys_FlushContext(esys_context, signHandle);
        goto_if_error(r, "Flushing context", error);

        signHandle = ESYS_TR_NONE;
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error: GetTime", error);

    r = Esys_FlushContext(esys_context, signHandle);
    goto_if_error(r, "Error: FlushContext", error);

    return EXIT_SUCCESS;

 error:

    if (signHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, signHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup signHandle failed.");
        }
    }
    return failure_return;
}
