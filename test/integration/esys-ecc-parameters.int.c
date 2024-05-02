/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for EXIT_FAILURE, EXIT_SUCCESS

#include "test-esys.h"        // for EXIT_SKIP, test_invoke_esys
#include "tss2_common.h"      // for TSS2_RC
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_ECC_Parameters, ESYS...
#include "tss2_tpm2_types.h"  // for TPM2_ECC_NIST_P256, TPM2_RC_1, TPM2_RC_...

#define LOGMODULE test
#include "util/log.h"         // for SAFE_FREE, LOG_WARNING, goto_if_error

/** Test the ESYS function Esys_ECC_Parameters.
 *
 * Tested ESYS commands:
 *  - Esys_ECC_Parameters() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */
int
test_esys_ecc_parameters(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    int failure_return = EXIT_FAILURE;

    TPMI_ECC_CURVE curveID  = TPM2_ECC_NIST_P256;
    TPMS_ALGORITHM_DETAIL_ECC *parameters;

    r = Esys_ECC_Parameters(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        curveID,
        &parameters);

    if (r == TPM2_RC_CURVE + TPM2_RC_P + TPM2_RC_1) {
        LOG_WARNING("Curve TPM2_ECC_NIST_P256 not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error: ECC_Parameters", error);

    SAFE_FREE(parameters);

    return EXIT_SUCCESS;

 error:
    SAFE_FREE(parameters);

    return failure_return;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_ecc_parameters(esys_context);
}
