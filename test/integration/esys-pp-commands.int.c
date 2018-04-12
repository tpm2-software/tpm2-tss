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
