#include <stdbool.h>

#include "log.h"
#include "test.h"
#include "test_utils/test-options.h"
#include "test_utils/context-util.h"

/**
 * This program is a template for integration tests (ones that use the TCTI
 * and the SAPI contexts / API directly). It does nothing more than parsing
 * command line options that allow the caller (likely a script) to specify
 * which TCTI to use for the test.
 */
int
main (int   argc,
      char *argv[])
{
    TSS2_RC rc;
    TSS2_SYS_CONTEXT *sapi_context;
    int ret;
    test_opts_t opts = {
        .tcti_type      = TCTI_DEFAULT,
        .device_file    = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port    = PORT_DEFAULT,
    };

    get_test_opts_from_env (&opts);
    if (sanity_check_test_opts (&opts) != 0)
        exit (1);
    sapi_context = sapi_init_from_opts (&opts);
    if (sapi_context == NULL)
        exit (1);
    rc = Tss2_Sys_Startup(sapi_context, TPM_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM_RC_INITIALIZE)
        print_fail("TPM Startup FAILED! Response Code : 0x%x", rc);
    ret = test_invoke (sapi_context);
    sapi_teardown_full (sapi_context);
    return ret;
}
