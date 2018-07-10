/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"

#include "test-esapi.h"
#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * Test the ESAPI function Esys_PP_Commands.
 * If the test requires physical presence, the test is skipped.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    int failure_return = EXIT_FAILURE;

    ESYS_TR auth_handle = ESYS_TR_RH_PLATFORM;
    TPML_CC setList = {
        .count = 1,
        .commandCodes = { TPM2_CC_PP_Commands }
    };
    TPML_CC clearList = {0};

    r = Esys_PP_Commands(esys_context, auth_handle,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &setList, &clearList);

    if (r == TPM2_RC_COMMAND_CODE) {
        LOG_WARNING("Command TPM2_PP_Commands not supported by TPM.");
        failure_return = EXIT_SKIP;
    }

    if (r == (TPM2_RC_WARN  | TPM2_RC_PP)) {
        LOG_INFO("Command TPM2_PP_Commands requires physical presence.");
        return EXIT_SUCCESS;
    }

    if ((r & ~TPM2_RC_N_MASK) == TPM2_RC_BAD_AUTH) {
        /* Platform authorization not possible test will be skipped */
        LOG_WARNING("Platform authorization not possible.");
        failure_return = EXIT_SKIP;
    }
    goto_if_error(r, "Error: PP_Commands", error);

    return EXIT_SUCCESS;

 error:
    return failure_return;
}
