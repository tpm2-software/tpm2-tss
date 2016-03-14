#include <tcti/tcti_device.h>
#include "tcti_util.h"

TSS2_RC InitDeviceTctiContext( const TCTI_DEVICE_CONF *driverConfig, TSS2_TCTI_CONTEXT **tctiContext, const char *deviceTctiName )
{
    size_t size;

    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = InitDeviceTcti(NULL, &size, driverConfig, 0, 0, deviceTctiName );
    if( rval != TSS2_RC_SUCCESS )
        return rval;

    *tctiContext = malloc(size);

    rval = InitDeviceTcti(*tctiContext, &size, driverConfig, TCTI_MAGIC, TCTI_VERSION, deviceTctiName );
    return rval;
}

TSS2_RC TeardownDeviceTcti(TSS2_TCTI_CONTEXT *tctiContext)
{
    ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->finalize( tctiContext );

    return TSS2_RC_SUCCESS;
}
