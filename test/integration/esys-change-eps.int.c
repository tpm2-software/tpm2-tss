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

/* Test the ESAPI function Esys_ChangeEPS */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    ESYS_TR authHandle = ESYS_TR_RH_PLATFORM;

    r = Esys_ChangeEPS(
        esys_context,
        authHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE);

    if (r == TPM2_RC_COMMAND_CODE) {
        LOG_WARNING("Command TPM2_ChangeEPS not supported by TPM.");
        return  EXIT_SKIP;
        goto error;
    }

    if (r == (TPM2_RC_BAD_AUTH | TPM2_RC_S | TPM2_RC_1)) {
        /* Platform authorization not possible test will be skipped */
        LOG_WARNING("Platform authorization not possible.");
        return EXIT_SKIP;
    }

    goto_if_error(r, "Error: ChangeEPS", error);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}
