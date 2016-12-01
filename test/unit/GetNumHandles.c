#include <stdlib.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "sapi/tpm20.h"
#include "sysapi_util.h"

/**
 * Test to be sure we get back the expected # of command handles for
 * common command code: TPM_CC_PolicyPCR.
 */
static void
GetNumCommandHandles_PolicyPCR_unit (void **state)
{
    int num_handles;
    TPM_CC command_code = TPM_CC_PolicyPCR;

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
    TPM_CC command_code = TPM_CC_HMAC_Start;

    num_handles = GetNumResponseHandles (command_code);
    assert_int_equal (num_handles, 1);
}

/**
 * Tests to ensure that GetNumCommandHandles and GetNumResponseHandles
 * returns 0 for unknown command codes.
 * Since 0 is a valid number here it may make more sense to return something
 * to indicate an error condition. Probaly best to catch unknown command
 * codes as early as possible?
 */
static void
GetNumCommandHandles_LAST_plus_one (void **state)
{
    int num_handles;
    TPM_CC command_code = TPM_CC_LAST + 1;

    num_handles = GetNumCommandHandles (command_code);
    assert_int_equal (num_handles, 0);
}

static void
GetNumResponseHandles_LAST_plus_one (void **state)
{
    int num_handles;
    TPM_CC command_code = TPM_CC_LAST + 1;

    num_handles = GetNumResponseHandles (command_code);
    assert_int_equal (num_handles, 0);
}

int
main (int   argc,
      char *argv[])
{
    const UnitTest tests [] = {
        unit_test (GetNumCommandHandles_PolicyPCR_unit),
        unit_test (GetNumResponseHandles_HMAC_Start_unit),
        unit_test (GetNumCommandHandles_LAST_plus_one),
        unit_test (GetNumResponseHandles_LAST_plus_one),
    };
    return run_tests (tests);
}
