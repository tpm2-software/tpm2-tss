#include <stdlib.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>
#include <sapi/tpm20.h>

#include "sys_api_marshalUnmarshal.h"
#include "sysapi_util.h"

/**
 * This tests the "common case" for the CheckOverflow. We define this as:
 * nexData > buffer, nextData + size <= bufferSize.
 */
void
CheckOverflow_good (void **state)
{
    TSS2_RC rc;
    UINT8 *buffer = 0x0, *nextData = (UINT8*)0x2;
    UINT32 bufferSize = 0x4, size = 0x2;

    rc = CheckOverflow (buffer, bufferSize, nextData, size);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
/**
 * This tests an edge case where nextData == buffer and bufferSize == size.
 * CheckOverflow should be successful in this case.
 */
void
CheckOverflow_whole_buffer (void **state)
{
    TSS2_RC rc;
    UINT8 *buffer = 0x0, *nextData = buffer;
    UINT32 bufferSize = 0x4, size = 0x4;

    rc = CheckOverflow (buffer, bufferSize, nextData, size);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
/**
 * Test the case that CheckOverflow is designed to catch. Specifically this
 * is the case where nextData > buffer, nextData + size > bufferSize
 */
void
CheckOverflow_overflow(void **state)
{
    TSS2_RC rc;
    UINT8 *buffer = (UINT8*)0x1, *nextData = (UINT8*)0x4;
    UINT32 bufferSize = 0x5, size = 0x6;

    rc = CheckOverflow (buffer, bufferSize, nextData, size);
    assert_int_equal (rc, TSS2_SYS_RC_INSUFFICIENT_CONTEXT);
}
/**
 * Test an edge case for the CheckOverflow function: buffer == nextData,
 * nextData + size < bufferSize.
 */
void
CheckOverflow_buf_next_equal (void **state)
{
    TSS2_RC rc;
    UINT8 *buffer = (UINT8*)0x5, *nextData = buffer;
    UINT32 bufferSize = 0x5, size = 0x1;

    rc = CheckOverflow (buffer, bufferSize, nextData, size);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
/**
 * This tests another edge case: nextData in this case is beyond the end of
 * the provided buffer.
 */
void
CheckOverflow_nextData_gt_buffer_end (void **state)
{
    TSS2_RC rc;
    UINT32 bufferSize = 0x1, size = 0x5;
    UINT8 *buffer = (UINT8*)0x5, *nextData = buffer + size;

    rc = CheckOverflow (buffer, bufferSize, nextData, size);
    assert_int_equal (rc, TSS2_SYS_RC_INSUFFICIENT_CONTEXT);
}
/**
 * Pass the CheckDataPointers function a NULL first parameter.
 * This should return a bad reference error.
 */
void
CheckDataPointers_null_buffer (void **state)
{
    TSS2_RC rc;
    UINT8 *buffer = NULL, *nextData = (UINT8*)5;

    rc = CheckDataPointers (buffer, &nextData);
    assert_int_equal (rc, TSS2_SYS_RC_BAD_REFERENCE);
}
/**
 * Pass the CheckDataPointers function a reference to a null pointer
 * in the second parameter. This should result in a bad reference RC.
 */
void
CheckDataPointers_null_nextData (void **state)
{
    TSS2_RC rc;
    UINT8 *buffer = (UINT8*)5, *nextData = NULL;

    rc = CheckDataPointers (buffer, &nextData);
    assert_int_equal (rc, TSS2_SYS_RC_BAD_REFERENCE);
}
/**
 * Pass the CheckDataPointers function a NULL second paraemter. This should
 * result in a bad reference RC.
 */
void
CheckDataPointers_null_nextData_ptr (void **state)
{
    TSS2_RC rc;
    UINT8 *buffer = (UINT8*)5, **nextData = NULL;

    rc = CheckDataPointers (buffer, nextData);
    assert_int_equal (rc, TSS2_SYS_RC_BAD_REFERENCE);
}
/**
 * Test an error case where nextData < buffer. Regardless of the size of the
 * data buffer this should fail.
 */
void
CheckDataPointers_nextData_lt_buffer_start (void **state)
{
    TSS2_RC rc;
    UINT8 *buffer = (UINT8*)0x5, *nextData = buffer - 1;

    rc = CheckDataPointers (buffer, &nextData);
    assert_int_equal (rc, TSS2_SYS_RC_BAD_REFERENCE);
}

int
main (void)
{
    const UnitTest tests [] = {
        unit_test (CheckOverflow_good),
        unit_test (CheckOverflow_whole_buffer),
        unit_test (CheckOverflow_overflow),
        unit_test (CheckOverflow_buf_next_equal),
        unit_test (CheckOverflow_nextData_gt_buffer_end),
        unit_test (CheckDataPointers_null_buffer),
        unit_test (CheckDataPointers_null_nextData),
        unit_test (CheckDataPointers_null_nextData_ptr),
        unit_test (CheckDataPointers_nextData_lt_buffer_start),
    };
    return run_tests (tests);
}
