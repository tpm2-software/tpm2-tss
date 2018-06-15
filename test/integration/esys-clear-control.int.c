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

/*
 * Test the ESAPI function Esys_ClearControl.
 * The clear command will be disabled and with Esys_Clear it will
 * be checked whether clear is disabled.
 */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    ESYS_TR auth_handle = ESYS_TR_RH_PLATFORM;
    TPMI_YES_NO disable = TPM2_YES;

    r = Esys_ClearControl(
        esys_context,
        auth_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        disable);

    goto_if_error(r, "Error: ClearControl", error);

    r = Esys_Clear (
        esys_context,
        auth_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE);
    goto_error_if_not_failed(r, "Error: ClockSet", error);

    disable = TPM2_NO;

    r = Esys_ClearControl(
        esys_context,
        auth_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        disable);

    goto_if_error(r, "Error: ClearControl", error);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}
