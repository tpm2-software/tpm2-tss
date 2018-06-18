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
 * Test the ESAPI function Esys_HierarchyControl.
 * The owner hierarchy will be disabled and with Esys_ClockSet it will
 * be checked whether the owner hierarchy is disabled
 */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    ESYS_TR authHandle_handle = ESYS_TR_RH_PLATFORM;
    TPMI_RH_ENABLES enable = TPM2_RH_OWNER;
    TPMI_YES_NO state = TPM2_NO;

    r = Esys_HierarchyControl(
        esys_context,
        authHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        enable,
        state);

    if ((r & (~TPM2_RC_N_MASK & ~TPM2_RC_H & ~TPM2_RC_S & ~TPM2_RC_P)) == TPM2_RC_BAD_AUTH) {
        /* Platform authorization not possible test will be skipped */
        LOG_WARNING("Platform authorization not possible.");
        return EXIT_SKIP;
    }

    goto_if_error(r, "Error: HierarchyControl", error);

    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;
    UINT64 newTime = 0xffffff;

    r = Esys_ClockSet(esys_context,
                      auth_handle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      newTime);
    goto_error_if_not_failed(r, "Error: ClockSet", error);

    state = TPM2_YES;

    r = Esys_HierarchyControl(
        esys_context,
        authHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        enable,
        state);
    goto_if_error(r, "Error: HierarchyControl", error);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}
