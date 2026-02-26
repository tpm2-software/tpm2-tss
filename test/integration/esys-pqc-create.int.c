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

#include "tss2_common.h"     // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_esys.h"       // for Esys_Free, ESYS_TR_NONE, Esys_FlushContext
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPMA_OBJECT_*, TPM2_ALG_*

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR

/** Test that ML-KEM and ML-DSA primary keys can be created via
 *  Esys_CreatePrimary.
 *
 * An ML-KEM-1024 decrypt key and an ML-DSA-65 signing key are created under
 * the owner hierarchy and then flushed.
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_FlushContext() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_pqc_create(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;

    ESYS_TR mlkem_handle = ESYS_TR_NONE;
    ESYS_TR mldsa_handle = ESYS_TR_NONE;

    TPM2B_PUBLIC        *mlkem_pub      = NULL;
    TPM2B_CREATION_DATA *mlkem_cdata    = NULL;
    TPM2B_DIGEST        *mlkem_chash    = NULL;
    TPMT_TK_CREATION    *mlkem_cticket = NULL;

    TPM2B_PUBLIC        *mldsa_pub      = NULL;
    TPM2B_CREATION_DATA *mldsa_cdata    = NULL;
    TPM2B_DIGEST        *mldsa_chash    = NULL;
    TPMT_TK_CREATION    *mldsa_cticket = NULL;

    TPM2B_AUTH authValuePrimary = { .size = 0, .buffer = {} };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0, .buffer = {0} },
            .data     = { .size = 0, .buffer = {0} },
        },
    };

    TPM2B_DATA outsideInfo = { .size = 0, .buffer = {} };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValuePrimary);
    goto_if_error(r, "Error: TR_SetAuth", error);

    TPM2B_PUBLIC inPublicMLKEM = {
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

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitive, &inPublicMLKEM,
                           &outsideInfo, &creationPCR,
                           &mlkem_handle,
                           &mlkem_pub, &mlkem_cdata,
                           &mlkem_chash, &mlkem_cticket);
    goto_if_error(r, "Error: CreatePrimary (ML-KEM-1024)", error);

    TPM2B_PUBLIC inPublicMLDSA = {
        .size = 0,
        .publicArea = {
            .type    = TPM2_ALG_MLDSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                  TPMA_OBJECT_SIGN_ENCRYPT |
                                  TPMA_OBJECT_FIXEDTPM |
                                  TPMA_OBJECT_FIXEDPARENT |
                                  TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = { .size = 0 },
            .parameters.mldsaDetail = {
                .scheme = TPM2_MLDSA_65,
            },
            .unique.mldsa = { .size = 0, .buffer = {} },
        },
    };

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitive, &inPublicMLDSA,
                           &outsideInfo, &creationPCR,
                           &mldsa_handle,
                           &mldsa_pub, &mldsa_cdata,
                           &mldsa_chash, &mldsa_cticket);
    goto_if_error(r, "Error: CreatePrimary (ML-DSA-65)", error);

    r = Esys_FlushContext(esys_context, mlkem_handle);
    goto_if_error(r, "Error: FlushContext (ML-KEM)", error);
    mlkem_handle = ESYS_TR_NONE;

    r = Esys_FlushContext(esys_context, mldsa_handle);
    goto_if_error(r, "Error: FlushContext (ML-DSA)", error);
    mldsa_handle = ESYS_TR_NONE;

    Esys_Free(mlkem_pub);
    Esys_Free(mlkem_cdata);
    Esys_Free(mlkem_chash);
    Esys_Free(mlkem_cticket);
    Esys_Free(mldsa_pub);
    Esys_Free(mldsa_cdata);
    Esys_Free(mldsa_chash);
    Esys_Free(mldsa_cticket);
    return EXIT_SUCCESS;

error:
    if (mlkem_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, mlkem_handle) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup mlkem_handle failed.");
    }
    if (mldsa_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, mldsa_handle) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup mldsa_handle failed.");
    }
    Esys_Free(mlkem_pub);
    Esys_Free(mlkem_cdata);
    Esys_Free(mlkem_chash);
    Esys_Free(mlkem_cticket);
    Esys_Free(mldsa_pub);
    Esys_Free(mldsa_cdata);
    Esys_Free(mldsa_chash);
    Esys_Free(mldsa_cticket);
    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_pqc_create(esys_context);
}
