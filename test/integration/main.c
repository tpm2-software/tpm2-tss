#include <stdbool.h>
#include <stdlib.h>

#define LOGMODULE test
#include "util/log.h"
#include "test.h"
#include "test-options.h"
#include "context-util.h"

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
    TSS2_SYS_CONTEXT *sapi_context;
    int ret;
    test_opts_t opts = {
        .tcti_type      = TCTI_DEFAULT,
        .device_file    = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port    = PORT_DEFAULT,
    };

    get_test_opts_from_env (&opts);
    if (sanity_check_test_opts (&opts) != 0) {
        LOG_ERROR("Checking test options");
        return 99; /* fatal error */
    }
    sapi_context = sapi_init_from_opts (&opts);
    if (sapi_context == NULL) {
        LOG_ERROR("SAPI context not initialized");
        return 99; /* fatal error */
    }

    ret = test_invoke (sapi_context);

    sapi_teardown_full (sapi_context);

    return ret;
}
