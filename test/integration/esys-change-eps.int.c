/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/* Test the ESAPI function Esys_ChangeEPS */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

    ESYS_TR authHandle = ESYS_TR_RH_PLATFORM;

    r = Esys_ChangeEPS(
        esys_context,
        authHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE);
    goto_if_error(r, "Error: ChangeEPS", error);

    return 0;

 error:
    return r;
}
