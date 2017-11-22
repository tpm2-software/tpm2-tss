#include "inttypes.h"
#include "log.h"
#include "sapi-util.h"
#include "test.h"

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC      rc             = TPM2_RC_SUCCESS;
    TPM2_HANDLE  primary_handle = 0;
    /* session parameters */
    /* command session info */
    TSS2L_SYS_AUTH_COMMAND  sessions_cmd         = {
        .auths = {{ .sessionHandle = TPM2_RS_PW }},
        .count = 1
    };
    /* response session info */
    TSS2L_SYS_AUTH_RESPONSE  sessions_rsp         = {
        .auths = { 0 },
        .count = 0
    };

    rc = create_primary_rsa_2048_aes_128_cfb (sapi_context, &primary_handle);
    if (rc != TSS2_RC_SUCCESS) {
        print_log ("failed to create primary: 0x%" PRIx32, rc);
        return rc;
    }

    rc = Tss2_Sys_EvictControl (sapi_context,
                                TPM2_RH_OWNER,
                                primary_handle,
                                &sessions_cmd,
                                0x81000000,
                                &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        print_log ("failed to make key 0x%" PRIx32 " persistent: 0x%" PRIx32,
                   primary_handle, rc);
    }

    return rc;
}
