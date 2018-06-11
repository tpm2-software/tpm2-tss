/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/* Test the ESAPI function Esys_ECC_Parameters */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

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
        LOG_WARNING("Curve TPM2_ECC_NIST_P256 supported by TPM.");
        r = 77; /* Skip */
        goto error;
    }
    goto_if_error(r, "Error: ECC_Parameters", error);

    return 0;

 error:
    return r;
}
