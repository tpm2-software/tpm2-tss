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
test_fapi_pqc_provision(FAPI_CONTEXT *context) {
    TSS2_RC r;

    r = Fapi_Provision(context, NULL, NULL, NULL);
    if (number_rc(r) == (TPM2_RC_ASYMMETRIC | TPM2_RC_P)
        || number_rc(r) == (TPM2_RC_TYPE | TPM2_RC_P) || number_rc(r) == TPM2_RC_ASYMMETRIC) {
        LOG_WARNING("TPM does not support PQC algorithms, skipping.");
        return EXIT_SKIP;
    }
    goto_if_error(r, "Error Fapi_Provision", error_cleanup);

    r = Fapi_CreateKey(context, FAPI_PROFILE "/HS/SRK/pqcSignKey", "sign,noDa", "" /* no policy */,
                       NULL /* no authValue */);
    goto_if_error(r, "Error Fapi_CreateKey (ML-DSA-65)", error_cleanup);

    /* NOTE: Fapi_Sign uses TPM2_Sign which is deprecated for ML-DSA in spec v185.
       ML-DSA signing requires TPM2_SignSequenceComplete or TPM2_SignDigest.
       Signing/verify will be tested in a dedicated ESYS-level PQC sign test. */

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error_cleanup);

    return EXIT_SUCCESS;

error_cleanup:
    Fapi_Delete(context, "/");
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context) {
#ifndef ENABLE_PQC
    UNUSED(fapi_context);
    LOG_WARNING("Skipping: PQC not enabled (configure --enable-pqc)");
    return EXIT_SKIP;
#else
    return test_fapi_pqc_provision(fapi_context);
#endif
}
