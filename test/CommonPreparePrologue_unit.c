#include <stdlib.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>
#include <tpm20.h>

static void
CommonPreparePrologue_null_sys_context_unit (void **state)
{
    TSS2_RC rc;

    rc = CommonPreparePrologue (NULL, 0);
    assert_int_equal (rc, TSS2_SYS_RC_BAD_REFERENCE);
}

int
main (int argc, char* arvg[])
{
    const UnitTest tests[] = {
        unit_test(CommonPreparePrologue_null_sys_context_unit),
    };
    return run_tests (tests);
}
