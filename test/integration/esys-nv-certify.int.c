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
 * This test is intended to test the command Esys_NV_Certify.
 * We create a RSA primary signing key which will be used as signing key
 * for the NV data.
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

    ESYS_TR nvHandle_handle;
    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_READ_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD
                ),
            .authPolicy = {
                 .size = 0,
                 .buffer = {},
             },
            .dataSize = 32,
        }
    };

    r = Esys_NV_DefineSpace(esys_context,
                            ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &auth,
                            &publicInfo,
                            &nvHandle_handle);
    goto_if_error(r, "Error esys define nv space", error);

    UINT16 offset = 0;
    TPM2B_MAX_NV_BUFFER nv_test_data = { .size = 20,
                                         .buffer={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                  1, 2, 3, 4, 5, 6, 7, 8, 9}};

    r = Esys_NV_Write(esys_context,
                      nvHandle_handle,
                      nvHandle_handle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      &nv_test_data,
                      offset);
    goto_if_error(r, "Error esys nv write", error);

    TPM2B_ATTEST *certifyInfo;
    TPMT_SIGNATURE *signature;
    TPM2B_DATA qualifyingData = {0};
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };

    r = Esys_NV_Certify(
        esys_context,
        signHandle,
        ESYS_TR_RH_OWNER,
        nvHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        &qualifyingData,
        &inScheme,
        20,
        0,
        &certifyInfo,
        &signature);
    goto_if_error(r, "Error: NV_Certify", error);

   r = Esys_NV_UndefineSpace(esys_context,
                              ESYS_TR_RH_OWNER,
                              nvHandle_handle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE
                              );
    goto_if_error(r, "Error: NV_UndefineSpace", error);

    r = Esys_FlushContext(esys_context,signHandle);
    goto_if_error(r, "Error: FlushContext", error);

    return 0;

 error:
    return 1;
}
