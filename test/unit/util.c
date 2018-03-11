#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2-tcti/tcti.h"
#define LOGMODULE unit_util
#include "util/log.h"

ssize_t
__wrap_write (int fd, const void *buffer, size_t buffer_size)
{
    LOG_DEBUG ("writing %zd bytes from 0x%" PRIxPTR " to fd: %d",
               buffer_size, (uintptr_t)buffer, fd);
    return mock_type (ssize_t);
}

/*
 * A test case for a successful call to the receive function. This requires
 * that the context and the command buffer be valid (including the size
 * field being set appropriately). The result should be an RC indicating
 * success and the size parameter be updated to reflect the size of the
 * data received.
 */
static void
util_write_all_simple_success_test (void **state)
{
    ssize_t ret;
    uint8_t buf [10];

    will_return (__wrap_write, sizeof (buf));
    ret = write_all (99, buf, sizeof (buf));
    assert_int_equal(ret, sizeof (buf));
}
int
main(int argc, char* argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (util_write_all_simple_success_test),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
