/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
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
 ***********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_sys.h"

#define LOGMODULE test
#include "util/log.h"
#include "test.h"

/**
 * This program contains integration test for SAPI Tss2_Sys_GetRandom.
 * First, this test is checking the return code to make sure the
 * SAPI is executed correctly(return code should return TPM2_RC_SUCCESS).
 * Second, the SAPI is called twice to make sure the return randomBytes
 * are different by comparing the two randomBytes through memcmp.
 * It might not be the best test for random bytes generator but
 * at least this test shows the return randomBytes are different.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPM2B_DIGEST randomBytes1 = {sizeof (TPM2B_DIGEST) - 2,};
    TPM2B_DIGEST randomBytes2 = {sizeof (TPM2B_DIGEST) - 2,};
    int bytes = 20;

    LOG_INFO("GetRandom tests started.");
    rc = Tss2_Sys_GetRandom(sapi_context, 0, bytes, &randomBytes1, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("GetRandom FAILED! Response Code : %x", rc);
        exit(1);
    }
    rc = Tss2_Sys_GetRandom(sapi_context, 0, bytes, &randomBytes2, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("GetRandom FAILED! Response Code : %x", rc);
        exit(1);
    }
    if(memcmp(&randomBytes1, &randomBytes2, bytes) == 0) {
        LOG_ERROR("Comparison FAILED! randomBytes 0x%p & 0x%p are the same.", &randomBytes1, &randomBytes2);
        exit(1);
    }
    LOG_INFO("GetRandom Test Passed!");
    return 0;
}
