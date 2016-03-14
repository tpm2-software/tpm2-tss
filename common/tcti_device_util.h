#include <tss2/tpm20.h>
#include <tcti/tcti_device.h>

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC InitDeviceTctiContext( const TCTI_DEVICE_CONF *config, TSS2_TCTI_CONTEXT **tctiContext, const char *deviceTctiName );
TSS2_RC TeardownDeviceTcti(TSS2_TCTI_CONTEXT *tctiContext);

#ifdef __cplusplus
}
#endif
