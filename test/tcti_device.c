#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include <tss2/tpm20.h>
#include "tcti_device_test.h"
#include "sysapi/include/tcti_util.h"

static void
tcti_dev_init_size_test (void **state)
{
    assert_int_equal(tcti_dev_init_size (state),
                     sizeof (TSS2_TCTI_CONTEXT_INTEL));
}

int
main(int argc, char* argv[])
{
    const UnitTest tests[] = {
        unit_test(tcti_dev_init_size_test),
    };
    return run_tests(tests);
}
