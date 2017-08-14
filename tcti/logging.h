#include "sapi/tpm20.h"

#include "tcti_util.h"

#define TCTI_LOG_CALLBACK_INVOKE(ctx, type, format, ...) \
    TCTI_LOG_CALLBACK(ctx)(TCTI_LOG_DATA(ctx), type, format, ##__VA_ARGS__)
#define TCTI_LOG( ctx, type, format, ...) \
    (TCTI_LOG_CALLBACK( ctx ) != NULL) ? \
      TCTI_LOG_CALLBACK_INVOKE( ctx, type, format, ##__VA_ARGS__) : 0

#define TCTI_LOG_BUFFER_CALLBACK_INVOKE( ctx, type, data, length ) \
    TCTI_LOG_BUFFER_CALLBACK( ctx )( TCTI_LOG_DATA(ctx), type, data, length )
#define TCTI_LOG_BUFFER( ctx, type, data, length ) \
    (TCTI_LOG_BUFFER_CALLBACK( ctx ) != NULL) ? \
      TCTI_LOG_BUFFER_CALLBACK_INVOKE( ctx, type, data, length ) : 0

int tcti_log_callback(
    void          *data,
    printf_type   type,
    const char    *format,
    ...
    );
