/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/* Test the ESAPI function Esys_ClockSet and Esys_ReadClock */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{

    uint32_t r = 0;

    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;
    UINT64 newTime = 0xffffff;

    r = Esys_ClockSet(esys_context,
                      auth_handle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      newTime
                      );
    goto_if_error(r, "Error: ClockSet", error);

    TPM2_CLOCK_ADJUST rateAdjust = TPM2_CLOCK_MEDIUM_FASTER;

    r = Esys_ClockRateAdjust(esys_context,
                             auth_handle,
                             ESYS_TR_PASSWORD,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             rateAdjust);
    goto_if_error(r, "Error: ClockRateAdjust", error);


    TPMS_TIME_INFO *currentTime;

    r = Esys_ReadClock(esys_context,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       &currentTime);
    goto_if_error(r, "Error: ReadClock", error);

    return 0;

 error:
    return 1;
}
