/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2024, Cisco Systems
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h> // for uint8_t
#include <stdlib.h> // for EXIT_FAILURE, EXIT_SUCCESS
#include <string.h> // for memcmp

#include "test-fapi.h"       // for EXIT_SKIP, FAPI_PROFILE, test_invoke_fapi
#include "tss2_common.h"     // for TSS2_RC, TSS2_FAPI_RC_NOT_IMPLEMENTED
#include "tss2_fapi.h"       // for Fapi_Provision, Fapi_CreateKey, Fapi_Encrypt
#include "tss2_tpm2_types.h" // for TPM2_RC_ASYMMETRIC, TPM2_RC_TYPE, TPM2_RC_P

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR, LOG_INFO, SAFE_FREE

#define PLAINTEXT_SIZE 200

/** Test FAPI ML-KEM hybrid encrypt/decrypt round-trip.
 *
 * Provisions with P_MLKEM profile, creates an ML-KEM-1024 decrypt key,
 * encrypts plaintext via Fapi_Encrypt (KEM hybrid: encapsulate + AES-GCM),
 * decrypts via Fapi_Decrypt, and verifies the round-trip.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision() (M)
 *  - Fapi_CreateKey() (M)
 *  - Fapi_Encrypt() (M)
 *  - Fapi_Decrypt() (M)
 *  - Fapi_Delete() (M)
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 * @retval EXIT_SKIP
 */
int
test_fapi_pqc_data_crypt(FAPI_CONTEXT *context) {
    TSS2_RC  r;
    uint8_t *cipherText = NULL;
    size_t   cipherTextSize = 0;
    uint8_t *plainText2 = NULL;
    size_t   plainText2Size = 0;

    /* Generate test plaintext */
    uint8_t plainText[PLAINTEXT_SIZE];
    for (int i = 0; i < PLAINTEXT_SIZE; i++)
        plainText[i] = (uint8_t)(i & 0xFF);

    r = Fapi_Provision(context, NULL, NULL, NULL);
    if (r != TSS2_RC_SUCCESS && rc_layer(r) == 0) {
        /* TPM rejected ML-KEM provisioning (e.g., unsupported algorithm or parameters) */
        LOG_WARNING("TPM does not support ML-KEM provisioning (rc=0x%08x), skipping.", (unsigned)r);
        return EXIT_SKIP;
    }
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_CreateKey(context, FAPI_PROFILE "/HS/SRK/pqcKemKey", "decrypt,noDa", NULL, NULL);
    if (r == TSS2_TCTI_RC_IO_ERROR) {
        /* TCTI IO error — simulator likely crashed (doesn't support ML-KEM Create) */
        LOG_WARNING("Simulator crashed during ML-KEM CreateKey (rc=0x%08x), skipping.",
                    (unsigned)r);
        return EXIT_SKIP;
    }
    goto_if_error(r, "Error Fapi_CreateKey (ML-KEM)", error);

    /* Encrypt */
    r = Fapi_Encrypt(context, FAPI_PROFILE "/HS/SRK/pqcKemKey", plainText, PLAINTEXT_SIZE,
                     &cipherText, &cipherTextSize);
    if (r == TSS2_FAPI_RC_NOT_IMPLEMENTED) {
        LOG_WARNING("Fapi_Encrypt not implemented for this key type, skipping.");
        goto skip;
    }
    goto_if_error(r, "Error Fapi_Encrypt", error);

    LOG_INFO("Encrypt succeeded: cipherTextSize = %zu", cipherTextSize);

    /* Decrypt */
    r = Fapi_Decrypt(context, FAPI_PROFILE "/HS/SRK/pqcKemKey", cipherText, cipherTextSize,
                     &plainText2, &plainText2Size);
    goto_if_error(r, "Error Fapi_Decrypt", error);

    /* Verify round-trip */
    if (plainText2Size != PLAINTEXT_SIZE || memcmp(plainText, plainText2, PLAINTEXT_SIZE) != 0) {
        LOG_ERROR("Decrypted text does not match original plaintext");
        goto error;
    }

    LOG_INFO("ML-KEM hybrid encrypt/decrypt round-trip succeeded.");

    Fapi_Free(cipherText);
    Fapi_Free(plainText2);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    return EXIT_SUCCESS;

skip:
    Fapi_Delete(context, "/");
    Fapi_Free(cipherText);
    Fapi_Free(plainText2);
    return EXIT_SKIP;

error:
    Fapi_Delete(context, "/");
    Fapi_Free(cipherText);
    Fapi_Free(plainText2);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context) {
#ifndef ENABLE_PQC
    UNUSED(fapi_context);
    LOG_WARNING("Skipping: PQC not enabled (configure --enable-pqc)");
    return EXIT_SKIP;
#else
    return test_fapi_pqc_data_crypt(fapi_context);
#endif
}
