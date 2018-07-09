/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#include "test-esapi.h"
#define LOGMODULE test
#include "util/log.h"

/* Test the ESAPI function Esys_SetAlgorithmSet */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    int failure_return = EXIT_FAILURE;

    UINT32 algorithmSet = 0;

    r = Esys_SetAlgorithmSet(
        esys_context,
        ESYS_TR_RH_PLATFORM,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        algorithmSet);

    if (r == TPM2_RC_COMMAND_CODE) {
        LOG_WARNING("Command TPM2_SetAlgorithmSet not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }

    if ((r & ~TPM2_RC_N_MASK) == TPM2_RC_BAD_AUTH) {
        /* Platform authorization not possible test will be skipped */
        LOG_WARNING("Platform authorization not possible.");
        failure_return = EXIT_SKIP;
    }

    goto_if_error(r, "Error: SetAlgorithmSet", error);

    return EXIT_SUCCESS;

 error:
    return failure_return;
}
