/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

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
    uint32_t r = 0;

    ESYS_TR auth_handle = ESYS_TR_RH_PLATFORM;
    TPML_CC setList = {
        .count = 1,
        .commandCodes = { TPM2_CC_PP_Commands }
    };
    TPML_CC clearList = {0};

    r = Esys_PP_Commands(esys_context, auth_handle,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &setList, &clearList);
    if (r == (TPM2_RC_WARN  | TPM2_RC_PP)) {
        LOG_INFO("Command TPM2_PP_Commands requires physical presence.");
        return 0;
    }
    goto_if_error(r, "Error: PP_Commands", error);

    return 0;

 error:
    return r;
}
