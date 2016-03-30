#include <stdio.h>
#include <tcti/tcti_device.h>
#include <stdbool.h>
#include "tcti/logging.h"
#include <setjmp.h>
#include <cmocka.h>

/* Determine the size of a TCTI context structure. Requires calling the
 * initialization function for the device TCTI with the first parameter
 * (the TCTI context) NULL.
 */
size_t
tcti_dev_init_size (void **state)
{
    void *my_state = *state;
    size_t tcti_size = 0;
    TSS2_RC ret = TSS2_RC_SUCCESS;

    ret = InitDeviceTcti (NULL, &tcti_size, NULL);
    if (ret != TSS2_RC_SUCCESS)
        return 0;
    else
        return tcti_size;
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
void
tcti_dev_init_log (void **state)
{
    void *my_state = *state;
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

bool
tcti_dev_log_called (void **state)
{
    void *my_state = *state;
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
    return called;
}
/* end tcti_dev_init_log */
