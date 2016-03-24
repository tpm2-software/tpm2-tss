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

static void
tcti_dev_init_log_test (void **state)
{
    tcti_dev_init_log (state);
}

static void
tcti_dev_log_called_test (void **state)
{
    assert_true (tcti_dev_log_called (state));
}

int
main(int argc, char* argv[])
{
    const UnitTest tests[] = {
        unit_test(tcti_dev_init_size_test),
        unit_test(tcti_dev_init_log_test),
        unit_test(tcti_dev_log_called_test),
    };
    return run_tests(tests);
}
