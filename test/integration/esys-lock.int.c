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

/* Test the ESAPI functions related to TPM locks  */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    r = Esys_DictionaryAttackLockReset(
        esys_context,
        ESYS_TR_RH_LOCKOUT,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE);
    goto_if_error(r, "Error: DictionaryAttackLockReset", error);

    UINT32 newMaxTries = 3;
    UINT32 newRecoveryTime = 3600;
    UINT32 lockoutRecovery = 1000;

    r = Esys_DictionaryAttackParameters(esys_context, ESYS_TR_RH_LOCKOUT,
                                        ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                        ESYS_TR_NONE,
                                        newMaxTries, newRecoveryTime,
                                        lockoutRecovery);
    goto_if_error(r, "Error: DictionaryAttackParameters", error);

    r = Esys_NV_GlobalWriteLock(esys_context, ESYS_TR_RH_PLATFORM,
                                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);

    if (r == (TPM2_RC_BAD_AUTH | TPM2_RC_S | TPM2_RC_1)) {
        /* Platform authorization not possible test will be skipped */
        LOG_WARNING("Platform authorization not possible.");
        return 77;
    }
    goto_if_error(r, "Error: NV_GlobalWriteLock", error);

    return EXIT_SUCCESS;

  error:
    return EXIT_FAILURE;
}
