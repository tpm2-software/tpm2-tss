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
 * This test is intended to test RSA encryption / decryption. with password
 * authentication.
 * We create a RSA primary key (Esys_CreatePrimary) for every crypto action
 * This key will be used for encrytion/decryption in with the schemes:
 * TPM2_ALG_NULL, TPM2_ALG_RSAES, and TPM2_ALG_OAEP
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
                               &primaryHandle_handle, &outPublic, &creationData,
                               &creationHash, &creationTicket);
        goto_if_error(r, "Error esys create primary", error);

        r = esys_GetResourceObject(esys_context, primaryHandle_handle,
                                   &primaryHandle_node);
        goto_if_error(r, "Error Esys GetResourceObject", error);

        LOG_INFO("Created Primary with handle 0x%08x...",
                 primaryHandle_node->rsrc.handle);

        r = Esys_TR_SetAuth(esys_context, primaryHandle_handle,
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
        r = Esys_RSA_Encrypt(esys_context, primaryHandle_handle, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &plain, &scheme,
                             &null_data, &cipher);
        goto_if_error(r, "Error esys rsa encrypt", error);

        TPM2B_PUBLIC_KEY_RSA *plain2;
        r = Esys_RSA_Decrypt(esys_context, primaryHandle_handle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             cipher, &scheme, &null_data, &plain2);
        goto_if_error(r, "Error esys rsa decrypt", error);

        if (mode > 0 && !memcmp(&plain.buffer[0], &plain2->buffer[0], plain_size)) {
            LOG_ERROR("plain texts are not equal for mode %i", mode);
        }
    }
    return 0;

 error:
    return 1;
}
