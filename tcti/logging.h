#include <tss2/tpm20.h>

#include "tcti_util.h"

#define TCTI_LOG_CALLBACK_INVOKE(ctx, type, format, ...) \
    TCTI_LOG_CALLBACK(ctx)(TCTI_LOG_DATA(ctx), type, format, ##__VA_ARGS__)
#define TCTI_LOG( ctx, type, format, ...) \
    (TCTI_LOG_CALLBACK( ctx ) != NULL) ? \
      TCTI_LOG_CALLBACK_INVOKE( ctx, type, format, ##__VA_ARGS__) : 0
