/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
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

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test Esys_ECDH_ZGen.  based on an ECC key
 * created with Esys_CreatePrimary and data produce by the command Esys_Ephemeral.
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
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
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
                     .mode.aes = TPM2_ALG_ECB,
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

    TPMI_ECC_CURVE curveID = TPM2_ECC_NIST_P256;
    TPM2B_ECC_POINT *Q;
    UINT16 counter;

    r = Esys_EC_Ephemeral(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        curveID,
        &Q,
        &counter);
    goto_if_error(r, "Error: EC_Ephemeral", error);

    TPM2B_ECC_POINT inQsB = {
        .size = 0,
        .point = outPublic->publicArea.unique.ecc
    };
    TPM2B_ECC_POINT inQeB = *Q;
    TPMI_ECC_KEY_EXCHANGE inScheme = TPM2_ALG_ECDH;
    TPM2B_ECC_POINT *outZ1;
    TPM2B_ECC_POINT *outZ2;

    r = Esys_ZGen_2Phase(
        esys_context,
        eccHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inQsB,
        &inQeB,
        inScheme,
        counter,
        &outZ1,
        &outZ2);
    goto_if_error(r, "Error: ZGen_2Phase", error);

    r = Esys_FlushContext(esys_context, eccHandle);
    goto_if_error(r, "Flushing context", error);

    return 0;

 error:
    LOG_ERROR("\nError Code: %x\n", r);
    return 1;
}
