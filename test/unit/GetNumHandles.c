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
#include <stdlib.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_sys.h"
#include "sysapi_util.h"

/**
 * Test to be sure we get back the expected # of command handles for
 * common command code: TPM2_CC_PolicyPCR.
 */
static void
GetNumCommandHandles_PolicyPCR_unit (void **state)
{
    int num_handles;
    TPM2_CC command_code = TPM2_CC_PolicyPCR;

    num_handles = GetNumCommandHandles (command_code);
    assert_int_equal (num_handles, 1);
}

/**
 * Test to be sure we get back the expected * of
 */
static void
GetNumResponseHandles_HMAC_Start_unit (void **state)
{
    int num_handles;
    TPM2_CC command_code = TPM2_CC_HMAC_Start;

    num_handles = GetNumResponseHandles (command_code);
    assert_int_equal (num_handles, 1);
}

/**
 * Tests to ensure that GetNumCommandHandles and GetNumResponseHandles
 * returns 0 for unknown command codes.
 * Since 0 is a valid number here it may make more sense to return something
 * to indicate an error condition. It is probably best to catch unknown command
 * codes as early as possible?
 */
static void
GetNumCommandHandles_LAST_plus_one (void **state)
{
    int num_handles;
    TPM2_CC command_code = TPM2_CC_LAST + 1;

    num_handles = GetNumCommandHandles (command_code);
    assert_int_equal (num_handles, 0);
}

static void
GetNumResponseHandles_LAST_plus_one (void **state)
{
    int num_handles;
    TPM2_CC command_code = TPM2_CC_LAST + 1;

    num_handles = GetNumResponseHandles (command_code);
    assert_int_equal (num_handles, 0);
}

int
main (int   argc,
      char *argv[])
{
    const struct CMUnitTest tests [] = {
        cmocka_unit_test (GetNumCommandHandles_PolicyPCR_unit),
        cmocka_unit_test (GetNumResponseHandles_HMAC_Start_unit),
        cmocka_unit_test (GetNumCommandHandles_LAST_plus_one),
        cmocka_unit_test (GetNumResponseHandles_LAST_plus_one),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
