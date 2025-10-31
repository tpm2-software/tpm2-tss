/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright (c) 2025 - 2025, Huawei Technologies Co., Ltd.
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for NULL, EXIT_FAILURE, EXIT_SUCCESS, size_t
#include <string.h>           // for memcmp
#include "test-esys.h"        // for EXIT_SKIP, test_invoke_esys
#include "esys_int.h"         // for RSRC_NODE_T
#include "esys_iutil.h"       // for esys_GetResourceObject
#include "esys_types.h"       // for IESYS_RESOURCE
#include "tss2_common.h"      // for BYTE, TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_esys.h"        // for Esys_Free, ESYS_TR_NONE, Esys_FlushContext
#include "tss2_tpm2_types.h"  // for TPM2B_PUBLIC, TPM2B_MAX_BUFFER, TPM...

#define LOGMODULE test
#include "util/log.h"         // for goto_if_error, LOG_ERROR, LOG_INFO

/** This test is intended to test ECC encryption / decryption.
 *  with password authentication.
 * We create an ECC primary key (Esys_CreatePrimary) for every crypto action
 * This key will be used for encryption/decryption with KDF schemes:
 * TPM2_ALG_KDF1_SP800_56A and TPM2_ALG_NULL
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_FlushContext() (M)
 *  - Esys_ECC_Decrypt() (M)
 *  - Esys_ECC_Encrypt() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

int
test_esys_ecc_encrypt_decrypt(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    TPM2B_ECC_POINT *c1 = NULL;
    TPM2B_MAX_BUFFER *c2 = NULL;
    TPM2B_DIGEST *c3 = NULL;
    TPM2B_MAX_BUFFER *plain2 = NULL;

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
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
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL},
                 .scheme = { .scheme = TPM2_ALG_NULL },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = { .scheme = TPM2_ALG_NULL },
             },
            .unique.ecc = {
                 .x = { .size = 0, .buffer = {} },
                 .y = { .size = 0, .buffer = {} },
             },
        },
    };

    LOG_INFO("\nECC key will be created.");

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

    TPMT_KDF_SCHEME scheme;
    scheme.scheme = TPM2_ALG_KDF2;
    scheme.details.kdf2.hashAlg = TPM2_ALG_SHA256;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                        ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                        &inPublic, &outsideInfo, &creationPCR,
                        &primaryHandle, &outPublic, &creationData,
                        &creationHash, &creationTicket);
    goto_if_error(r, "Error esys create primary", error);
    Esys_Free(outPublic);
    outPublic = NULL;
    Esys_Free(creationData);
    creationData = NULL;
    Esys_Free(creationHash);
    creationHash = NULL;
    Esys_Free(creationTicket);
    creationTicket = NULL;

    r = Esys_TR_SetAuth(esys_context, primaryHandle,
                        &authValuePrimary);
    goto_if_error(r, "Error: TR_SetAuth", error);

    size_t plain_size = 16;
    TPM2B_MAX_BUFFER plain = {
        .size = plain_size,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
    };

    r = Esys_ECC_Encrypt(esys_context, primaryHandle, ESYS_TR_NONE,
                        ESYS_TR_NONE, ESYS_TR_NONE, &plain, &scheme,
                        &c1, &c2, &c3);
    goto_if_error(r, "Error esys ecc encrypt", error);

    r = Esys_ECC_Decrypt(esys_context, primaryHandle,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        c1, c2, c3, &scheme, &plain2);
    goto_if_error(r, "Error esys ecc decrypt", error);

    if (memcmp(&plain.buffer[0], &plain2->buffer[0], plain_size) != 0) {
        LOG_ERROR("plain texts are not equal");
        goto error;
    }

    LOG_INFO("ECC encryption/decryption successful");

    r = Esys_FlushContext(esys_context, primaryHandle);
    goto_if_error(r, "Error: FlushContext", error);

    Esys_Free(c1);
    Esys_Free(c2);
    Esys_Free(c3);
    Esys_Free(plain2);
    c1 = NULL;
    c2 = NULL;
    c3 = NULL;
    plain2 = NULL;

    return EXIT_SUCCESS;

 error:

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }
    if (outPublic != NULL) {
        Esys_Free(outPublic);
        outPublic = NULL;
    }
    if (creationData != NULL) {
        Esys_Free(creationData);
        creationData = NULL;
    }
    if (creationHash != NULL) {
        Esys_Free(creationHash);
        creationHash = NULL;
    }
    if (creationTicket != NULL) {
        Esys_Free(creationTicket);
        creationTicket = NULL;
    }
    if (c1 != NULL) {
        Esys_Free(c1);
        c1 = NULL;
    }
    if (c2 != NULL) {
        Esys_Free(c2);
        c2 = NULL;
    }
    if (c3 != NULL) {
        Esys_Free(c3);
        c3 = NULL;
    }
    if (plain2 != NULL) {
        Esys_Free(plain2);
        plain2 = NULL;
    }
    /* If the TPM doesn't support it return skip */
    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER)))
        return EXIT_SKIP;
    else
        return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_ecc_encrypt_decrypt(esys_context);
}
