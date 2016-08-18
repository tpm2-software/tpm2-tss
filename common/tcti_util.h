#ifndef TCTI_UTIL_H
#define TCTI_UTIL_H

#include <sapi/tpm20.h>
#ifndef _WIN32
#include <tcti/tcti_device.h>
#endif //_WIN32
#include <tcti/tcti_socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WIN32
TSS2_RC InitDeviceTctiContext( const TCTI_DEVICE_CONF *config, TSS2_TCTI_CONTEXT **tctiContext, const char *deviceTctiName );
#endif //_WIN32
TSS2_RC InitSocketTctiContext (const TCTI_SOCKET_CONF  *device_conf,
                               TSS2_TCTI_CONTEXT      **tcti_context);
void TeardownTctiContext(TSS2_TCTI_CONTEXT **tctiContext);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* TCTI_UTIL_H */
