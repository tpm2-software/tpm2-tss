#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_mu.h"
#include "tss2_tcti_device.h"
#include "tss2-tcti/tcti.h"

/*
 * Size of the TPM2 buffer used in these tests. In some cases this will be
 * the command sent (transmit tests) and in others it's used as the response
 * buffer returned by the TCTI. The only field used by the TCTI is the size
 * field.
 */
#define BUF_SIZE 20
static uint8_t tpm2_buf [BUF_SIZE] = {
    0x80, 0x02, /* TAG */
    0x00, 0x00, 0x00, 0x14, /* size (BUF_SIZE) */
    0x00, 0x00, 0x00, 0x00, /* rc (success) */
    0xde, 0xad, 0xbe, 0xef, /* junk data */
    0xca, 0xfe, 0xba, 0xbe,
    0xfe, 0xef
};
/**
 * When passed all NULL values ensure that we get back the expected RC
 * indicating bad values.
 */
static void
tcti_device_init_all_null_test (void **state)
{
    TSS2_RC rc;

    rc = Tss2_Tcti_Device_Init (NULL, NULL, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}
/* Determine the size of a TCTI context structure. Requires calling the
 * initialization function for the device TCTI with the first parameter
 * (the TCTI context) NULL.
 */
static void
tcti_device_init_size_test (void **state)
{
    size_t tcti_size = 0;
    TSS2_RC ret = TSS2_RC_SUCCESS;

    ret = Tss2_Tcti_Device_Init (NULL, &tcti_size, NULL);
    assert_int_equal (ret, TSS2_RC_SUCCESS);
}
/* wrap functions for read & write required to test receive / transmit */
ssize_t
__wrap_read (int fd, void *buf, size_t count)
{
    ssize_t ret = mock_type (ssize_t);
    uint8_t *buf_in = mock_type (uint8_t*);

    memcpy (buf, buf_in, ret);
    return ret;
}
ssize_t
__wrap_write (int fd, const void *buffer, size_t buffer_size)
{
    ssize_t ret = mock_type (ssize_t);
    uint8_t *buf_out = mock_type (uint8_t*);

    memcpy (buf_out, buffer, ret);
    return ret;
}

typedef struct {
    TSS2_TCTI_CONTEXT *ctx;
    size_t   buffer_size;
    size_t   data_size;
    uint8_t  buffer [TPM_HEADER_SIZE * 2];
} data_t;
/* Setup functions to create the context for the device TCTI */
static int
tcti_device_setup (void **state)
{
    size_t tcti_size = 0;
    TSS2_RC ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    ret = Tss2_Tcti_Device_Init (NULL, &tcti_size, NULL);
    assert_true (ret == TSS2_RC_SUCCESS);
    ctx = calloc (1, tcti_size);
    assert_non_null (ctx);
    ret = Tss2_Tcti_Device_Init (ctx, 0, "/dev/null");
    assert_true (ret == TSS2_RC_SUCCESS);

    *state = ctx;
    return 0;
}

static int
tcti_device_teardown (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;

    Tss2_Tcti_Finalize (ctx);
    free (ctx);

    return 0;

}
/*
 * This test ensures that the GetPollHandles function in the device TCTI
 * returns the expected value. Since this TCTI does not support async I/O
 * on account of limitations in the kernel it just returns the
 * NOT_IMPLEMENTED response code.
 */
static void
tcti_device_get_poll_handles_test (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;
    size_t num_handles = 5;
    TSS2_TCTI_POLL_HANDLE handles [5] = { 0 };
    TSS2_RC rc;

    rc = Tss2_Tcti_GetPollHandles (ctx, handles, &num_handles);
    assert_int_equal (rc, TSS2_TCTI_RC_NOT_IMPLEMENTED);
}
/*
 */
static void
tcti_device_receive_null_size_test (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (ctx);
    TSS2_RC rc;

    /* Keep state machine check in `receive` from returning error. */
    tcti_intel->state = TCTI_STATE_RECEIVE;
    rc = Tss2_Tcti_Receive (ctx,
                            NULL, /* NULL 'size' parameter */
                            NULL,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_REFERENCE);
    rc = Tss2_Tcti_Receive (ctx,
                            NULL, /* NULL 'size' parameter */
                            (uint8_t*)1, /* non-NULL buffer */
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_REFERENCE);
}
/*
 * A test case for a successful call to the receive function. This requires
 * that the context and the command buffer be valid (including the size
 * field being set appropriately). The result should be an RC indicating
 * success and the size parameter be updated to reflect the size of the
 * data received.
 */
static void
tcti_device_receive_one_call_success (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (ctx);
    TSS2_RC rc;
    /* output buffer for response */
    uint8_t buf_out [BUF_SIZE + 5] = { 0 };
    size_t size = BUF_SIZE + 5;

    /* Keep state machine check in `receive` from returning error. */
    tcti_intel->state = TCTI_STATE_RECEIVE;
    will_return (__wrap_read, TPM_HEADER_SIZE);
    will_return (__wrap_read, tpm2_buf);
    will_return (__wrap_read, BUF_SIZE - TPM_HEADER_SIZE);
    will_return (__wrap_read, &tpm2_buf [TPM_HEADER_SIZE]);
    rc = Tss2_Tcti_Receive (ctx,
                            &size,
                            buf_out,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_true (rc == TSS2_RC_SUCCESS);
    assert_int_equal (BUF_SIZE, size);
    assert_memory_equal (tpm2_buf, buf_out, size);
}
static void
tcti_device_receive_two_call_success (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (ctx);
    TSS2_RC rc;
    /* output buffer for response */
    uint8_t buf_out [BUF_SIZE + 5] = { 0 };
    size_t size = 0;

    /* Keep state machine check in `receive` from returning error. */
    tcti_intel->state = TCTI_STATE_RECEIVE;
    will_return (__wrap_read, TPM_HEADER_SIZE);
    will_return (__wrap_read, tpm2_buf);
    will_return (__wrap_read, BUF_SIZE - TPM_HEADER_SIZE);
    will_return (__wrap_read, &tpm2_buf [TPM_HEADER_SIZE]);
    rc = Tss2_Tcti_Receive (ctx,
                            &size,
                            NULL,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (size, BUF_SIZE);
    assert_true (size < BUF_SIZE + 5);
    rc = Tss2_Tcti_Receive (ctx,
                            &size,
                            buf_out,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_true (rc == TSS2_RC_SUCCESS);
    assert_int_equal (size, BUF_SIZE);
    assert_memory_equal (tpm2_buf, buf_out, size);
}
/*
 */
static void
tcti_device_receive_second_size_too_small_test (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (ctx);
    TSS2_RC rc;
    /* output buffer for response */
    uint8_t buf_out [BUF_SIZE + 5] = { 0 };
    size_t size = 0;

    /* Keep state machine check in `receive` from returning error. */
    tcti_intel->state = TCTI_STATE_RECEIVE;
    will_return (__wrap_read, TPM_HEADER_SIZE);
    will_return (__wrap_read, tpm2_buf);
    /* get the size of the buffer required to hold the response */
    rc = Tss2_Tcti_Receive (ctx,
                            &size,
                            NULL,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    assert_int_equal (size, BUF_SIZE);
    /* set 'size' to be less than the required size for the response */
    --size;
    rc = Tss2_Tcti_Receive (ctx,
                            &size,
                            buf_out,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_true (rc == TSS2_TCTI_RC_INSUFFICIENT_BUFFER);
}
/*
 * A test case for a successful call to the transmit function. This requires
 * that the context and the cmmand buffer be valid. The only indication of
 * success is the RC.
 */
static void
tcti_device_transmit_success (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)*state;
    TSS2_RC rc;
    /* output buffer for response */
    uint8_t buf_out [BUF_SIZE] = { 0 };

    will_return (__wrap_write, BUF_SIZE);
    will_return (__wrap_write, buf_out);
    rc = Tss2_Tcti_Transmit (ctx,
                             BUF_SIZE,
                             tpm2_buf);
    assert_true (rc == TSS2_RC_SUCCESS);
    assert_memory_equal (tpm2_buf, buf_out, BUF_SIZE);
}

int
main(int argc, char* argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_device_init_all_null_test),
        cmocka_unit_test(tcti_device_init_size_test),
        cmocka_unit_test_setup_teardown (tcti_device_get_poll_handles_test,
                                         tcti_device_setup,
                                         tcti_device_teardown),
        cmocka_unit_test_setup_teardown (tcti_device_receive_null_size_test,
                                         tcti_device_setup,
                                         tcti_device_teardown),
        cmocka_unit_test_setup_teardown (tcti_device_receive_one_call_success,
                                         tcti_device_setup,
                                         tcti_device_teardown),
        cmocka_unit_test_setup_teardown (tcti_device_receive_two_call_success,
                                         tcti_device_setup,
                                         tcti_device_teardown),
        cmocka_unit_test_setup_teardown (tcti_device_transmit_success,
                                         tcti_device_setup,
                                         tcti_device_teardown),
        cmocka_unit_test_setup_teardown (tcti_device_receive_second_size_too_small_test,
                                         tcti_device_setup,
                                         tcti_device_teardown),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
