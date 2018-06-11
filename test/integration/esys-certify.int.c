/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the command Esys_Certify.
 * We create a RSA primary signing key which will be used as signing key
 * and as object for the certify command.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

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
                        .mode.aes = TPM2_ALG_ECB,
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

    ESYS_TR signHandle;
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

    TPM2B_DATA qualifyingData = {0};
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    TPM2B_ATTEST *certifyInfo;
    TPMT_SIGNATURE *signature;

    r = Esys_Certify (
        esys_context,
        signHandle,
        signHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        &qualifyingData,
        &inScheme,
        &certifyInfo,
        &signature
        );
    goto_if_error(r, "Error: Certify", error);

    r = Esys_FlushContext(esys_context,signHandle);
    goto_if_error(r, "Error: FlushContext", error);

    return 0;

 error:
    return 1;
}
