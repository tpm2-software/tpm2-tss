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

/** Test MakeCredential / ActivateCredential with an ML-KEM endorsement key.
 *
 * An ML-KEM-1024 restricted decryption key serves as the EK; an RSA-2048
 * restricted signing key serves as the AK.  The credential roundtrip:
 *
 *   Esys_MakeCredential(ek, credential, ak_name) -> credentialBlob, secret
 *   Esys_ActivateCredential(ak, ek, credentialBlob, secret) -> certInfo
 *
 * asserts that the recovered certInfo matches the original credential.
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_TR_GetName() (M)
 *  - Esys_MakeCredential() (M)
 *  - Esys_ActivateCredential() (M)
 *  - Esys_FlushContext() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_pqc_credential(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;

    ESYS_TR ek_handle = ESYS_TR_NONE;
    ESYS_TR ak_handle = ESYS_TR_NONE;

    TPM2B_PUBLIC        *ek_pub         = NULL;
    TPM2B_CREATION_DATA *ek_cdata       = NULL;
    TPM2B_DIGEST        *ek_chash       = NULL;
    TPMT_TK_CREATION    *ek_cticket     = NULL;

    TPM2B_PUBLIC        *ak_pub         = NULL;
    TPM2B_CREATION_DATA *ak_cdata       = NULL;
    TPM2B_DIGEST        *ak_chash       = NULL;
    TPMT_TK_CREATION    *ak_cticket     = NULL;

    TPM2B_NAME             *ak_name       = NULL;
    TPM2B_ID_OBJECT        *credentialBlob = NULL;
    TPM2B_ENCRYPTED_SECRET *encSecret     = NULL;
    TPM2B_DIGEST           *certInfo      = NULL;

    TPM2B_DIGEST credential = {
        .size = 20,
        .buffer = { 0x01, 0x02, 0x03, 0x04, 0x05,
                    0x06, 0x07, 0x08, 0x09, 0x0a,
                    0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14 }
    };

    /* Auth values */
    TPM2B_AUTH ekAuth = { .size = 0, .buffer = {} };
    TPM2B_AUTH akAuth = { .size = 5, .buffer = { 5, 4, 3, 2, 1 } };

    TPM2B_SENSITIVE_CREATE inSensitiveEK = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0, .buffer = {0} },
            .data     = { .size = 0, .buffer = {0} },
        },
    };

    TPM2B_SENSITIVE_CREATE inSensitiveAK = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0, .buffer = {0} },
            .data     = { .size = 0, .buffer = {0} },
        },
    };
    inSensitiveAK.sensitive.userAuth = akAuth;

    TPM2B_DATA outsideInfo    = { .size = 0, .buffer = {} };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER,
                        &(TPM2B_AUTH){ .size = 0, .buffer = {} });
    goto_if_error(r, "Error: TR_SetAuth (owner)", error);

    /* ML-KEM-1024 EK: restricted decryption */
    TPM2B_PUBLIC inPublicEK = {
        .size = 0,
        .publicArea = {
            .type    = TPM2_ALG_MLKEM,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                  TPMA_OBJECT_RESTRICTED |
                                  TPMA_OBJECT_DECRYPT |
                                  TPMA_OBJECT_FIXEDTPM |
                                  TPMA_OBJECT_FIXEDPARENT |
                                  TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = { .size = 0 },
            .parameters.mlkemDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes    = TPM2_ALG_CFB,
                },
                .scheme = TPM2_MLKEM_1024,
            },
            .unique.mlkem = { .size = 0, .buffer = {} },
        },
    };

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_ENDORSEMENT,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitiveEK, &inPublicEK,
                           &outsideInfo, &creationPCR,
                           &ek_handle,
                           &ek_pub, &ek_cdata, &ek_chash, &ek_cticket);
    goto_if_error(r, "Error: CreatePrimary (ML-KEM EK)", error);

    r = Esys_TR_SetAuth(esys_context, ek_handle, &ekAuth);
    goto_if_error(r, "Error: TR_SetAuth (EK)", error);

    /* RSA-2048 AK: restricted signing */
    TPM2B_PUBLIC inPublicAK = {
        .size = 0,
        .publicArea = {
            .type    = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                  TPMA_OBJECT_RESTRICTED |
                                  TPMA_OBJECT_SIGN_ENCRYPT |
                                  TPMA_OBJECT_FIXEDTPM |
                                  TPMA_OBJECT_FIXEDPARENT |
                                  TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = { .size = 0 },
            .parameters.rsaDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme = {
                    .scheme = TPM2_ALG_RSASSA,
                    .details.rsassa.hashAlg = TPM2_ALG_SHA256,
                },
                .keyBits  = 2048,
                .exponent = 0,
            },
            .unique.rsa = { .size = 0, .buffer = {} },
        },
    };

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitiveAK, &inPublicAK,
                           &outsideInfo, &creationPCR,
                           &ak_handle,
                           &ak_pub, &ak_cdata, &ak_chash, &ak_cticket);
    goto_if_error(r, "Error: CreatePrimary (RSA AK)", error);

    r = Esys_TR_SetAuth(esys_context, ak_handle, &akAuth);
    goto_if_error(r, "Error: TR_SetAuth (AK)", error);

    r = Esys_TR_GetName(esys_context, ak_handle, &ak_name);
    goto_if_error(r, "Error: TR_GetName (AK)", error);

    /* MakeCredential: public-key operation, no auth required */
    r = Esys_MakeCredential(esys_context, ek_handle,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            &credential, ak_name,
                            &credentialBlob, &encSecret);
    goto_if_error(r, "Error: MakeCredential", error);

    r = Esys_ActivateCredential(esys_context, ak_handle, ek_handle,
                                ESYS_TR_PASSWORD, ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                credentialBlob, encSecret,
                                &certInfo);
    goto_if_error(r, "Error: ActivateCredential", error);

    if (certInfo->size != credential.size ||
        memcmp(certInfo->buffer, credential.buffer, credential.size) != 0) {
        LOG_ERROR("ActivateCredential roundtrip FAILED: certInfo mismatch.");
        goto error;
    }

    r = Esys_FlushContext(esys_context, ak_handle);
    goto_if_error(r, "Error: FlushContext (AK)", error);
    ak_handle = ESYS_TR_NONE;

    r = Esys_FlushContext(esys_context, ek_handle);
    goto_if_error(r, "Error: FlushContext (EK)", error);
    ek_handle = ESYS_TR_NONE;

    Esys_Free(ek_pub);    Esys_Free(ek_cdata);  Esys_Free(ek_chash);  Esys_Free(ek_cticket);
    Esys_Free(ak_pub);    Esys_Free(ak_cdata);  Esys_Free(ak_chash);  Esys_Free(ak_cticket);
    Esys_Free(ak_name);
    Esys_Free(credentialBlob);
    Esys_Free(encSecret);
    Esys_Free(certInfo);
    return EXIT_SUCCESS;

error:
    if (ak_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, ak_handle) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup ak_handle failed.");
    }
    if (ek_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, ek_handle) != TSS2_RC_SUCCESS)
            LOG_ERROR("Cleanup ek_handle failed.");
    }
    Esys_Free(ek_pub);    Esys_Free(ek_cdata);  Esys_Free(ek_chash);  Esys_Free(ek_cticket);
    Esys_Free(ak_pub);    Esys_Free(ak_cdata);  Esys_Free(ak_chash);  Esys_Free(ak_cticket);
    Esys_Free(ak_name);
    Esys_Free(credentialBlob);
    Esys_Free(encSecret);
    Esys_Free(certInfo);
    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_pqc_credential(esys_context);
}
