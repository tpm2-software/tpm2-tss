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
 * This test is intended to test the ESAPI command CreateLoaded.
 * We start by creating a primary key (Esys_CreatePrimary).
 * This primary key will be used as parent key for CreateLoaded.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

#ifdef TEST_SESSION
    ESYS_TR session;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE *nonceTpm;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    memset(&sessionAttributes, 0, sizeof sessionAttributes);

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1, &session,
                              &nonceTpm);

    goto_if_error(r, "Error: During initialization of session", error);
#endif /* TEST_SESSION */

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
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle_handle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esys create primary", error);

    r = Esys_TR_SetAuth(esys_context, primaryHandle_handle, &authValuePrimary);
    goto_if_error(r, "Setting the Primary's AuthValue", error);

    TPM2B_AUTH authValueObject = {
        .size = 5,
        .buffer = {6, 7, 8, 9, 10}
    };

    TPM2B_SENSITIVE_CREATE inSensitiveObject = {
        .size = 4,
        .sensitive = {
            .userAuth = authValueObject,
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    TPM2B_TEMPLATE inPublic_template = {0};
    ESYS_TR objectHandle_handle;
    TPM2B_PRIVATE *outPrivate2;
    TPM2B_PUBLIC *outPublic2;
    TPMT_PUBLIC  inPublic2 = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_SIGN_ENCRYPT |
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
                  .scheme = TPM2_ALG_ECDSA,
                  .details = {.ecdsa =
                              {.hashAlg = TPM2_ALG_SHA1}
                  }
              },
             .curveID = TPM2_ECC_NIST_P256,
             .kdf = {.scheme =
                     TPM2_ALG_NULL,.details = {}
              }
         },
        .unique.ecc = {
             .x = {.size = 0,.buffer = {}},
             .y = {.size = 0,.buffer = {}}
         },
    };

    size_t offset = 0;

    r = Tss2_MU_TPMT_PUBLIC_Marshal(&inPublic2, &inPublic_template.buffer[0],
                                    sizeof(TPMT_PUBLIC), &offset);
    goto_if_error(r, "Error Tss2_MU_TPMT_PUBLIC_Marshal", error);

    inPublic_template.size = offset;

    r = Esys_CreateLoaded(
        esys_context,
        primaryHandle_handle,
#ifdef TEST_SESSION
        session,
#else
        ESYS_TR_PASSWORD,
#endif
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inSensitiveObject,
        &inPublic_template,
        &objectHandle_handle,
        &outPrivate2,
        &outPublic2
        );
    if (r == TPM2_RC_COMMAND_CODE) {
        LOG_INFO("Command TPM2_CreateLoaded not supported by TPM.");

        r = Esys_FlushContext(esys_context, primaryHandle_handle);
        goto_if_error(r, "Flushing context", error);

        r = 77; /* Skip */
        goto error;
    } else {
        goto_if_error(r, "Error During CreateLoaded", error);

        r = Esys_FlushContext(esys_context, primaryHandle_handle);
        goto_if_error(r, "Flushing context", error);

        r = Esys_FlushContext(esys_context, objectHandle_handle);
        goto_if_error(r, "Flushing context", error);
    }

#ifdef TEST_SESSION
    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error: FlushContext", error);
#endif

    return 0;

 error:
    return r;
}
