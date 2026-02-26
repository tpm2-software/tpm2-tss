/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2024, Hewlett Packard Enterprise
 * All rights reserved.
 *******************************************************************************
 */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h> // for uint8_t
#include <stdlib.h> // for NULL, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h> // for strlen

#include "test-fapi.h"   // for EXIT_SKIP, FAPI_PROFILE, goto_if_error
#include "tss2_common.h" // for TSS2_RC, TSS2_RC_SUCCESS
#include "tss2_fapi.h"   // for Fapi_Provision, Fapi_CreateKey, Fapi_Sign

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, SAFE_FREE, LOG_ERROR

/** Test end-to-end FAPI provisioning and signing with an ML-DSA-65 key.
 *
 * Provisions the hierarchy under the P_MLDSA profile, creates an ML-DSA-65
 * leaf signing key, signs a digest, and verifies the signature.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision() (M)
 *  - Fapi_CreateKey() (M)
 *  - Fapi_Sign() (M)
 *  - Fapi_VerifySignature() (M)
 *  - Fapi_Delete() (M)
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_pqc_provision(FAPI_CONTEXT *context)
{
    TSS2_RC r;

    uint8_t *signature      = NULL;
    size_t   signature_size = 0;
    char    *public_key     = NULL;
    char    *certificate    = NULL;

    /* 32-byte digest representing SHA-256("pqc-test-message") */
    uint8_t digest[32] = {
        0x8e, 0x7a, 0x1b, 0xc3, 0x45, 0xf2, 0x67, 0x9a,
        0x11, 0x02, 0x33, 0x84, 0x75, 0xe6, 0xc7, 0xd8,
        0x09, 0xfa, 0x2b, 0x4c, 0x3d, 0x6e, 0x7f, 0x90,
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18
    };

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error_cleanup);

    r = Fapi_CreateKey(context, FAPI_PROFILE "/HS/SRK/pqcSignKey",
                       "sign,noDa",
                       "" /* no policy */,
                       NULL /* no authValue */);
    goto_if_error(r, "Error Fapi_CreateKey (ML-DSA-65)", error_cleanup);

    r = Fapi_Sign(context, FAPI_PROFILE "/HS/SRK/pqcSignKey",
                  NULL /* padding */,
                  digest, sizeof(digest),
                  &signature, &signature_size,
                  &public_key, &certificate);
    goto_if_error(r, "Error Fapi_Sign", error_cleanup);

    r = Fapi_VerifySignature(context,
                             FAPI_PROFILE "/HS/SRK/pqcSignKey",
                             digest, sizeof(digest),
                             signature, signature_size);
    goto_if_error(r, "Error Fapi_VerifySignature", error_cleanup);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error_cleanup);

    SAFE_FREE(signature);
    SAFE_FREE(public_key);
    SAFE_FREE(certificate);
    return EXIT_SUCCESS;

error_cleanup:
    Fapi_Delete(context, "/");
    SAFE_FREE(signature);
    SAFE_FREE(public_key);
    SAFE_FREE(certificate);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_pqc_provision(fapi_context);
}
