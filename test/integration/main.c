#include <stdbool.h>

#include "log.h"
#include "test.h"
#include "test-options.h"
#include "context-util.h"
#include "common/debug.h"
#include "main.h"

#define LEVEL_STRING_SIZE 50
TSS2_TCTI_CONTEXT *resMgrTctiContextInt = 0;

void ErrorHandlerInt( UINT32 rval )
{
    UINT32 errorLevel = rval & TSS2_ERROR_LEVEL_MASK;
    char levelString[LEVEL_STRING_SIZE + 1];

    switch( errorLevel )
    {
        case TSS2_TPM_ERROR_LEVEL:
            strncpy( levelString, "TPM", LEVEL_STRING_SIZE );
            break;
        case TSS2_APP_ERROR_LEVEL:
            strncpy( levelString, "Application", LEVEL_STRING_SIZE );
            break;
        case TSS2_SYS_ERROR_LEVEL:
            strncpy( levelString, "System API", LEVEL_STRING_SIZE );
            break;
        case TSS2_SYS_PART2_ERROR_LEVEL:
            strncpy( levelString, "System API TPM encoded", LEVEL_STRING_SIZE );
            break;
        case TSS2_TCTI_ERROR_LEVEL:
            strncpy( levelString, "TCTI", LEVEL_STRING_SIZE );
            break;
        case TSS2_RESMGRTPM_ERROR_LEVEL:
            strncpy( levelString, "Resource Mgr TPM encoded", LEVEL_STRING_SIZE );
            break;
        case TSS2_RESMGR_ERROR_LEVEL:
            strncpy( levelString, "Resource Mgr", LEVEL_STRING_SIZE );
            break;
        case TSS2_DRIVER_ERROR_LEVEL:
            strncpy( levelString, "Driver", LEVEL_STRING_SIZE );
            break;
        default:
            strncpy( levelString, "Unknown Level", LEVEL_STRING_SIZE );
            break;
	}

    sprintf_s( errorString, errorStringSize, "%s Error: 0x%x\n", levelString, rval );
}

void DelayInt( UINT16 delay)
{
    volatile UINT32 i, j;

    for( j = 0; j < delay; j++ )
    {
        for( i = 0; i < 10000000; i++ )
            ;
    }
}

void CleanupInt()
{
    fflush( stdout );

    if( resMgrTctiContextInt != 0 )
    {
        PlatformCommand( resMgrTctiContextInt, MS_SIM_POWER_OFF );
        TeardownTctiContextInt( &resMgrTctiContextInt );
    }

    exit(1);
}

void TeardownTctiContextInt(TSS2_TCTI_CONTEXT **tctiContext)
{
    if (*tctiContext != NULL) {
        tss2_tcti_finalize( *tctiContext );
        free (*tctiContext);
        *tctiContext = NULL;
    }
}



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
