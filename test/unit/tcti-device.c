#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_mu.h"
#include "tss2_tcti_device.h"
#include "tss2-tcti/tcti.h"

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
    return mock_type (ssize_t);
}

typedef struct {
    TSS2_TCTI_CONTEXT *ctx;
    uint8_t *buffer;
    size_t   buffer_size;
    size_t   data_size;
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
tcti_device_setup_with_command (void **state)
{
    TSS2_RC rc;
    data_t *data;
    size_t index = 0;

    data = malloc (sizeof (data_t));
    assert_non_null (data);
    tcti_device_setup ((void**)&data->ctx);
    data->buffer_size = 1024;
    data->data_size   = 512;
    data->buffer = malloc (data->buffer_size);
    rc = Tss2_MU_TPM2_ST_Marshal (TPM2_ST_NO_SESSIONS, data->buffer, data->buffer_size, &index);
    assert_true (rc == TSS2_RC_SUCCESS);
    rc = Tss2_MU_UINT32_Marshal (data->data_size, data->buffer, data->buffer_size, &index);
    assert_true (rc == TSS2_RC_SUCCESS);
    rc = Tss2_MU_TPM2_CC_Marshal (TPM2_CC_Create, data->buffer, data->buffer_size, &index);
    assert_true (rc == TSS2_RC_SUCCESS);

    *state = data;
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
static int
tcti_device_teardown_with_data (void **state)
{
    data_t *data = *state;

    tcti_device_teardown ((void**)&data->ctx);
    free (data);
    return 0;
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
    data_t *data = *state;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (data->ctx);

    /* Keep state machine check in `receive` from returning error. */
    tcti_intel->state = TCTI_STATE_RECEIVE;
    will_return (__wrap_read, TPM_HEADER_SIZE);
    will_return (__wrap_read, data->buffer);
    will_return (__wrap_read, data->data_size - TPM_HEADER_SIZE);
    will_return (__wrap_read, &data->buffer [TPM_HEADER_SIZE]);
    rc = Tss2_Tcti_Receive (data->ctx,
                            &data->buffer_size,
                            data->buffer,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_true (rc == TSS2_RC_SUCCESS);
    assert_int_equal (data->data_size, data->buffer_size);
}
static void
tcti_device_receive_two_call_success (void **state)
{
    data_t *data = *state;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT_INTEL *tcti_intel = tcti_context_intel_cast (data->ctx);
    size_t size = 0;

    /* Keep state machine check in `receive` from returning error. */
    tcti_intel->state = TCTI_STATE_RECEIVE;
    will_return (__wrap_read, TPM_HEADER_SIZE);
    will_return (__wrap_read, data->buffer);
    will_return (__wrap_read, data->data_size - TPM_HEADER_SIZE);
    will_return (__wrap_read, &data->buffer [TPM_HEADER_SIZE]);
    rc = Tss2_Tcti_Receive (data->ctx,
                            &size,
                            NULL,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    printf ("got size: %zd", size);
    assert_int_equal (size, data->data_size);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
    rc = Tss2_Tcti_Receive (data->ctx,
                            &data->buffer_size,
                            data->buffer,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_true (rc == TSS2_RC_SUCCESS);
}
/*
 * A test case for a successful call to the transmit function. This requires
 * that the context and the cmmand buffer be valid. The only indication of
 * success is the RC.
 */
static void
tcti_device_transmit_success (void **state)
{
    data_t *data = *state;
    TSS2_RC rc;

    will_return (__wrap_write, data->buffer_size);
    rc = Tss2_Tcti_Transmit (data->ctx,
                             data->buffer_size,
                             data->buffer);
    assert_true (rc == TSS2_RC_SUCCESS);
}

int
main(int argc, char* argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tcti_device_init_all_null_test),
        cmocka_unit_test(tcti_device_init_size_test),
        cmocka_unit_test_setup_teardown (tcti_device_receive_null_size_test,
                                         tcti_device_setup,
                                         tcti_device_teardown),
        cmocka_unit_test_setup_teardown (tcti_device_receive_one_call_success,
                                  tcti_device_setup_with_command,
                                  tcti_device_teardown),
        cmocka_unit_test_setup_teardown (tcti_device_receive_two_call_success,
                                         tcti_device_setup_with_command,
                                         tcti_device_teardown_with_data),
        cmocka_unit_test_setup_teardown (tcti_device_transmit_success,
                                  tcti_device_setup_with_command,
                                  tcti_device_teardown_with_data),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
