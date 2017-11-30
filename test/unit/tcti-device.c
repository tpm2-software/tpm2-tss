#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "sapi/tss2_mu.h"
#include "tcti/tcti_device.h"
#include "tcti/tcti.h"

/**
 * When passed all NULL values ensure that we get back the expected RC
 * indicating bad values.
 */
static void
tcti_device_init_all_null_test (void **state)
{
    TSS2_RC rc;

    rc = InitDeviceTcti (NULL, NULL, NULL);
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

    ret = InitDeviceTcti (NULL, &tcti_size, NULL);
    assert_int_equal (ret, TSS2_RC_SUCCESS);
}
/**
 * When passed a non-NULL context blob and size the config structure must
 * also be non-NULL. No way to initialize the TCTI otherwise.
 */
static void
tcti_device_init_null_config_test (void **state)
{
    size_t tcti_size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT_INTEL tcti_intel = { 0 };
    TSS2_TCTI_CONTEXT *tcti_context = (TSS2_TCTI_CONTEXT*)&tcti_intel;

    rc = InitDeviceTcti (tcti_context, &tcti_size, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}

/* wrap functions for read & write required to test receive / transmit */
ssize_t
__wrap_read (int fd, void *buffer, size_t count)
{
    return mock_type (ssize_t);
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
static void
tcti_device_setup (void **state)
{
    size_t tcti_size = 0;
    TSS2_RC ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;
    TCTI_DEVICE_CONF conf = {
        .device_path = "/dev/null",
    };

    ret = InitDeviceTcti (NULL, &tcti_size, NULL);
    assert_true (ret == TSS2_RC_SUCCESS);
    ctx = calloc (1, tcti_size);
    assert_non_null (ctx);
    ret = InitDeviceTcti (ctx, 0, &conf);
    assert_true (ret == TSS2_RC_SUCCESS);
    *state = ctx;
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
    TSS2_TCTI_CONTEXT *ctx = *state;

    Tss2_Tcti_Finalize (ctx);
    free (ctx);
    return 0;
}
/*
 * A test case for a successful call to the receive function. This requires
 * that the context and the command buffer be valid (including the size
 * field being set appropriately). The result should be an RC indicating
 * success and the size parameter be updated to reflect the size of the
 * data received.
 */
static void
tcti_device_receive_success (void **state)
{
    data_t *data = *state;
    TSS2_RC rc;

    will_return (__wrap_read, data->data_size);
    rc = Tss2_Tcti_Receive (data->ctx,
                            &data->buffer_size,
                            data->buffer,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    assert_true (rc == TSS2_RC_SUCCESS);
    assert_int_equal (data->data_size, data->buffer_size);
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
        cmocka_unit_test (tcti_device_init_null_config_test),
        cmocka_unit_test_setup_teardown (tcti_device_receive_success,
                                  tcti_device_setup_with_command,
                                  tcti_device_teardown),
        cmocka_unit_test_setup_teardown (tcti_device_transmit_success,
                                  tcti_device_setup_with_command,
                                  tcti_device_teardown),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
