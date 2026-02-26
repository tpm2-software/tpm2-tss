/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2024, Hewlett Packard Enterprise
 * All rights reserved.
 *******************************************************************************
 */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h> // for NULL, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h> // for memcmp

#include "tss2_common.h"     // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_esys.h"       // for Esys_Free, ESYS_TR_NONE, Esys_FlushContext
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPMA_OBJECT_*, TPM2_ALG_*

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR

/** Test the ML-KEM encapsulate/decapsulate (KEM) roundtrip.
 *
 * An ML-KEM-1024 primary key is created under the owner hierarchy.
 * Esys_Encapsulate generates a ciphertext and encapsulator shared secret;
 * Esys_Decapsulate recovers the shared secret from the private key.  The
 * two values are compared to confirm correctness.
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_Encapsulate() (M)
 *  - Esys_Decapsulate() (M)
 *  - Esys_FlushContext() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_pqc_kem(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;

    ESYS_TR mlkem_handle = ESYS_TR_NONE;

    TPM2B_PUBLIC        *outPublic      = NULL;
    TPM2B_CREATION_DATA *creationData   = NULL;
    TPM2B_DIGEST        *creationHash   = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_KEM_CIPHERTEXT *ciphertext   = NULL;
    TPM2B_SHARED_SECRET  *enc_secret   = NULL;
    TPM2B_SHARED_SECRET  *dec_secret   = NULL;

    TPM2B_AUTH authValue = { .size = 5, .buffer = { 1, 2, 3, 4, 5 } };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0, .buffer = {0} },
            .data     = { .size = 0, .buffer = {0} },
        },
    };
    inSensitive.sensitive.userAuth = authValue;

    TPM2B_DATA outsideInfo    = { .size = 0, .buffer = {} };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type    = TPM2_ALG_MLKEM,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                  TPMA_OBJECT_DECRYPT |
                                  TPMA_OBJECT_FIXEDTPM |
                                  TPMA_OBJECT_FIXEDPARENT |
                                  TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = { .size = 0 },
            .parameters.mlkemDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme    = TPM2_MLKEM_1024,
            },
            .unique.mlkem = { .size = 0, .buffer = {} },
        },
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER,
                        &(TPM2B_AUTH){ .size = 0, .buffer = {} });
    goto_if_error(r, "Error: TR_SetAuth (owner)", error);

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitive, &inPublic,
                           &outsideInfo, &creationPCR,
                           &mlkem_handle,
                           &outPublic, &creationData,
                           &creationHash, &creationTicket);
    goto_if_error(r, "Error: CreatePrimary (ML-KEM-1024)", error);

    r = Esys_TR_SetAuth(esys_context, mlkem_handle, &authValue);
    goto_if_error(r, "Error: TR_SetAuth (ML-KEM key)", error);

    r = Esys_Encapsulate(esys_context, mlkem_handle,
                         ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                         &ciphertext, &enc_secret);
    goto_if_error(r, "Error: Encapsulate", error);

    r = Esys_Decapsulate(esys_context, mlkem_handle,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         ciphertext, &dec_secret);
    goto_if_error(r, "Error: Decapsulate", error);

    if (enc_secret->size != dec_secret->size ||
        memcmp(enc_secret->buffer, dec_secret->buffer, enc_secret->size) != 0) {
        LOG_ERROR("KEM roundtrip FAILED: shared secrets do not match.");
        goto error;
    }

    r = Esys_FlushContext(esys_context, mlkem_handle);
    goto_if_error(r, "Error: FlushContext", error);
    mlkem_handle = ESYS_TR_NONE;

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(ciphertext);
    Esys_Free(enc_secret);
    Esys_Free(dec_secret);
    return EXIT_SUCCESS;

error:
    if (mlkem_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, mlkem_handle) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup mlkem_handle failed.");
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(ciphertext);
    Esys_Free(enc_secret);
    Esys_Free(dec_secret);
    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_pqc_kem(esys_context);
}
