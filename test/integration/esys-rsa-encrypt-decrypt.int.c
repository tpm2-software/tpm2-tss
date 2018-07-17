/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/** This test is intended to test RSA encryption / decryption.
 *  with password
 * authentication.
 * We create a RSA primary key (Esys_CreatePrimary) for every crypto action
 * This key will be used for encryption/decryption in with the schemes:
 * TPM2_ALG_NULL, TPM2_ALG_RSAES, and TPM2_ALG_OAEP
 *
 * Tested ESAPI commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_FlushContext() (M)
 *  - Esys_RSA_Decrypt() (M)
 *  - Esys_RSA_Encrypt() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

int
test_esys_rsa_encrypt_decrypt(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

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
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL},
                 .scheme = { .scheme = TPM2_ALG_RSAES },
                 .keyBits = 2048,
                 .exponent = 0,
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

    RSRC_NODE_T *primaryHandle_node;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    for (int mode = 0; mode <= 2; mode++) {

        if (mode == 0) {
            inPublic.publicArea.parameters.rsaDetail.scheme.scheme =
                TPM2_ALG_NULL;
        } else if (mode == 1) {
            inPublic.publicArea.parameters.rsaDetail.scheme.scheme =
                TPM2_ALG_RSAES;
        } else if (mode == 2) {
            inPublic.publicArea.parameters.rsaDetail.scheme.scheme =
                TPM2_ALG_OAEP;
            inPublic.publicArea.parameters.rsaDetail.scheme.details.oaep.
                hashAlg = TPM2_ALG_SHA1;
        }

        r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                               ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                               &inPublic, &outsideInfo, &creationPCR,
                               &primaryHandle, &outPublic, &creationData,
                               &creationHash, &creationTicket);
        goto_if_error(r, "Error esys create primary", error);

        r = esys_GetResourceObject(esys_context, primaryHandle,
                                   &primaryHandle_node);
        goto_if_error(r, "Error Esys GetResourceObject", error);

        LOG_INFO("Created Primary with handle 0x%08x...",
                 primaryHandle_node->rsrc.handle);

        r = Esys_TR_SetAuth(esys_context, primaryHandle,
                            &authValuePrimary);
        goto_if_error(r, "Error: TR_SetAuth", error);

        size_t plain_size = 3;
        TPM2B_PUBLIC_KEY_RSA plain = {.size = plain_size,.buffer = {1, 2, 3}
        };
        TPMT_RSA_DECRYPT scheme;
        TPM2B_DATA null_data = {.size = 0,.buffer = {}
        };
        TPM2B_PUBLIC_KEY_RSA *cipher;

        if (mode == 0) {
            scheme.scheme = TPM2_ALG_NULL;
        } else if (mode == 1) {
            scheme.scheme = TPM2_ALG_RSAES;
        } else if (mode == 2) {
            scheme.scheme = TPM2_ALG_OAEP;
            scheme.details.oaep.hashAlg = TPM2_ALG_SHA1;
        }
        r = Esys_RSA_Encrypt(esys_context, primaryHandle, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &plain, &scheme,
                             &null_data, &cipher);
        goto_if_error(r, "Error esys rsa encrypt", error);

        TPM2B_PUBLIC_KEY_RSA *plain2;
        r = Esys_RSA_Decrypt(esys_context, primaryHandle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             cipher, &scheme, &null_data, &plain2);
        goto_if_error(r, "Error esys rsa decrypt", error);

        if (mode > 0 && memcmp(&plain.buffer[0], &plain2->buffer[0], plain_size)) {
            LOG_ERROR("plain texts are not equal for mode %i", mode);
            goto error;
        }

        r = Esys_FlushContext(esys_context, primaryHandle);
        goto_if_error(r, "Error: FlushContext", error);
    }
    return EXIT_SUCCESS;

 error:

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    return EXIT_FAILURE;
}

int
test_invoke_esapi(ESYS_CONTEXT * esys_context) {
    return test_esys_rsa_encrypt_decrypt(esys_context);
}
