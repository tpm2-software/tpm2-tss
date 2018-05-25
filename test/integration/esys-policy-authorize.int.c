/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
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
#include "tss2_mu.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the ESAPI policy authorization.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

    /*
     * 1. Create Primary. This primary will be used for PolicyAuthorize.
     */

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = authValuePrimary,
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
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT  |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_RSAPSS,
                      .details = {
                          .rsapss = { .hashAlg = TPM2_ALG_SHA1 }
                      }
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

    /*
     * 2. Create a trial policy with PolicyAuthorized. The name primary key
     *    will be passed and the primary key will be used to sign policies.
     */
    ESYS_TR sessionTrial;
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
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session", error);

    TPM2B_NAME *nameKeySign;
    TPM2B_NAME *keyQualifiedName;

    /* Dummy data for first call of PolicyAuthorize */
    TPM2B_DIGEST approvedPolicy = {0};
    TPM2B_NONCE policyRef = {0};
    TPMT_TK_VERIFIED  checkTicket = {
        .tag = TPM2_ST_VERIFIED,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}
    };

    r = Esys_ReadPublic(esys_context,
                        primaryHandle_handle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &outPublic,
                        &nameKeySign,
                        &keyQualifiedName);
    goto_if_error(r, "Error: ReadPublic", error);

    r = Esys_PolicyAuthorize(
        esys_context,
        sessionTrial,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &approvedPolicy,
        &policyRef,
        nameKeySign,
        &checkTicket
        );
    goto_if_error(r, "Error: PolicyAuthorize", error);

    TPM2B_DIGEST *policyAuthorizeDigest;
    r = Esys_PolicyGetDigest(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &policyAuthorizeDigest);
    goto_if_error(r, "Error: PolicyGetDigest", error);

    r = Esys_FlushContext(esys_context, sessionTrial);
    goto_if_error(r, "Error: FlushContext", error);


    r = Esys_FlushContext(esys_context, primaryHandle_handle);
    goto_if_error(r, "Error: FlushContext", error);

    return 0;

 error:
    return 1;
}
