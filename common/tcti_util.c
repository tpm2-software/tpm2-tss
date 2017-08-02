#include "tcti/tcti_device.h"
#include "common/debug.h"

TSS2_RC InitDeviceTctiContext( const TCTI_DEVICE_CONF *driverConfig, TSS2_TCTI_CONTEXT **tctiContext, const char *deviceTctiName )
{
    size_t size;

    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = InitDeviceTcti(NULL, &size, driverConfig );
    if( rval != TSS2_RC_SUCCESS )
        return rval;

    *tctiContext = malloc(size);

    DebugPrintf( NO_PREFIX, "Initializing %s Interface\n", deviceTctiName );
    rval = InitDeviceTcti(*tctiContext, &size, driverConfig );
    return rval;
}

TSS2_RC
InitSocketTctiContext (const TCTI_SOCKET_CONF  *device_conf,
                       TSS2_TCTI_CONTEXT      **tcti_context)
{
    size_t size;
    TSS2_RC rc;

    rc = InitSocketTcti (NULL, &size, device_conf, 0);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    *tcti_context = malloc (size);
    return InitSocketTcti (*tcti_context, &size, device_conf, 0);
}

void TeardownTctiContext(TSS2_TCTI_CONTEXT **tctiContext)
{
    if (*tctiContext != NULL) {
        tss2_tcti_finalize( *tctiContext );
        free (*tctiContext);
        *tctiContext = NULL;
    }
}
