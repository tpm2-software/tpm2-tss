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

/** Test the ESAPI function Esys_ClockSet and Esys_ReadClock. 
 *
 *\b Note: platform authorization needed.
 *
 * Tested ESAPI commands:
 *  - Esys_ClockRateAdjust() (M)
 *  - Esys_ClockSet() (M)
 *  - Esys_ReadClock() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */
int
test_esys_clockset(ESYS_CONTEXT * esys_context)
{

    TSS2_RC r;
    int failure_return = EXIT_FAILURE;

    ESYS_TR auth_handle = ESYS_TR_RH_PLATFORM;
    TPMS_TIME_INFO *currentTime;

    r = Esys_ReadClock(esys_context,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       &currentTime);
    goto_if_error(r, "Error: ReadClock", error);

    UINT64 newTime = currentTime->time + 01000;

    r = Esys_ClockSet(esys_context,
                      auth_handle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      newTime
                      );
    goto_if_error(r, "Error: ClockSet", error);

    if ((r & ~TPM2_RC_N_MASK) == TPM2_RC_BAD_AUTH) {
        /* Platform authorization not possible test will be skipped */
        LOG_WARNING("Platform authorization not possible.");
        failure_return = EXIT_SKIP;
        goto error;
    }

    r = Esys_ClockRateAdjust(esys_context,
                             auth_handle,
                             ESYS_TR_PASSWORD,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             TPM2_CLOCK_MEDIUM_FASTER);
    goto_if_error(r, "Error: ClockRateAdjust", error);

    r = Esys_ClockRateAdjust(esys_context,
                             auth_handle,
                             ESYS_TR_PASSWORD,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             TPM2_CLOCK_MEDIUM_SLOWER);
    goto_if_error(r, "Error: ClockRateAdjust", error);


    return EXIT_SUCCESS;

 error:
    return failure_return;
}

int
test_invoke_esapi(ESYS_CONTEXT * esys_context) {
    return test_esys_clockset(esys_context);
}
