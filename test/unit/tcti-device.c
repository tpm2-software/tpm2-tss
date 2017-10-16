#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "sapi/tss2_mu.h"
#include "tcti/tcti_device.h"
#include "tcti/logging.h"
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
    TSS2_TCTI_CONTEXT *tcti_context = (TSS2_TCTI_CONTEXT*)1;

    rc = InitDeviceTcti (tcti_context, &tcti_size, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}

/* begin tcti_dev_init_log */
/* This test configures the device TCTI with a logging callback and some user
 * data. It checks to be sure that the initialization function sets the
 * internal data in the TCTI to use / point to this data accordingly.
 */
int
tcti_dev_init_log_callback (void *data, printf_type type, const char *format, ...)
{
    return 0;
}
static void
tcti_device_init_log_test (void **state)
{
    size_t tcti_size = 0;
    uint8_t my_data = 0x9;
    TSS2_RC ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;
    TCTI_DEVICE_CONF conf = {
        "/dev/null", tcti_dev_init_log_callback, &my_data
    };

    ret = InitDeviceTcti (NULL, &tcti_size, NULL);
    assert_true (ret == TSS2_RC_SUCCESS);
    ctx = calloc (1, tcti_size);
    assert_non_null (ctx);
    ret = InitDeviceTcti (ctx, 0, &conf);
    assert_true (ret == TSS2_RC_SUCCESS);
    assert_true (TCTI_LOG_CALLBACK (ctx) == tcti_dev_init_log_callback);
    assert_true (*(uint8_t*)TCTI_LOG_DATA (ctx) == my_data);
    if (ctx)
        free (ctx);
}
/* end tcti dev_init_log */

/* begin tcti_dev_init_log_called */
/* Initialize TCTI context providing a pointer to a logging function and some
 * data. The test case calls the logging function through the TCTI interface
 * and checks to be sure that the function is called and that the user data
 * provided is what we expect. We detect that the logging function was called
 * by having it change the user data provided and then detecting this change.
 * The caller responsible for freeing the context.
 */
int
tcti_dev_log_callback (void *data, printf_type type, const char *format, ...)
{
    *(bool*)data = true;
    return 0;
}

static void
tcti_device_log_called_test (void **state)
{
    size_t tcti_size = 0;
    bool called = false;
    TSS2_RC ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;
    TCTI_DEVICE_CONF conf = {
        "/dev/null", tcti_dev_log_callback, &called
    };

    ret = InitDeviceTcti (NULL, &tcti_size, NULL);
    assert_true (ret == TSS2_RC_SUCCESS);
    ctx = calloc (1, tcti_size);
    assert_non_null (ctx);
    ret = InitDeviceTcti (ctx, 0, &conf);
    assert_true (ret == TSS2_RC_SUCCESS);
    if (ctx)
        free (ctx);
    /* the 'called' variable should be changed from false to true after this */
    TCTI_LOG (ctx, NO_PREFIX, "test log call");
    assert_true (called);
}
/* end tcti_dev_init_log */
/* wrap functions for read & write required to test receive / transmit */
ssize_t
__wrap_read (int fd, void *buffer, size_t count)
{
    return (ssize_t)mock ();
}
ssize_t
__wrap_write (int fd, const void *buffer, size_t buffer_size)
{
    return (ssize_t)mock ();
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
        .logCallback = NULL,
        .logData     = NULL
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
    rc = Tss2_MU_TPM_ST_Marshal (TPM_ST_NO_SESSIONS, data->buffer, data->buffer_size, &index);
    assert_true (rc == TSS2_RC_SUCCESS);
    rc = Tss2_MU_UINT32_Marshal (data->data_size, data->buffer, data->buffer_size, &index);
    assert_true (rc == TSS2_RC_SUCCESS);
    rc = Tss2_MU_TPM_CC_Marshal (TPM_CC_Create, data->buffer, data->buffer_size, &index);
    assert_true (rc == TSS2_RC_SUCCESS);

    *state = data;
    return 0;
}

static int
tcti_device_teardown (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = *state;

    tss2_tcti_finalize (ctx);
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
    rc = tss2_tcti_receive (data->ctx,
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
    rc = tss2_tcti_transmit (data->ctx,
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
        cmocka_unit_test (tcti_device_init_log_test),
        cmocka_unit_test (tcti_device_log_called_test),
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
