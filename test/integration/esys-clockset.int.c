/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
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
