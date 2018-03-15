/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
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

#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>

#include "tss2_esys.h"

#define LOGMODULE test
#include "util/log.h"
#include "test.h"
#include "sysapi_util.h"
#include "esys_types.h"
#include "esys_iutil.h"

#define checkerror(rc,msg,label) \
	if (rc != TSS2_RC_SUCCESS) { \
		LOG_ERROR("Error %s (%x) in Line %i: \n", msg, __LINE__, rc); \
		goto label; }

/*
 * This test is intended to test the ESAPI get capability command.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;
    TPM2_CAP                       capability = TPM2_CAP_TPM_PROPERTIES;
    UINT32                         property = TPM2_PT_LOCKOUT_COUNTER;
    UINT32                         propertyCount = 1;
    TPMS_CAPABILITY_DATA           *capabilityData;
    TPMI_YES_NO                    moreData;


    r = Esys_GetCapability(esys_context,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           capability, property, propertyCount,
                           &moreData, &capabilityData);

    goto_if_error(r, "Error esys get capability", error);

    return 0;

 error:
    return 1;
}
