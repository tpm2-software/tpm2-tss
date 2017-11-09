#include "inttypes.h"
#include "log.h"
#include "sapi-util.h"
#include "test.h"

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TPM_RC      rc             = TPM_RC_SUCCESS;
    TPM_HANDLE  primary_handle = 0;
    /* session parameters */
    /* command session info */
    TPMS_AUTH_COMMAND   session_cmd          = { .sessionHandle = TPM_RS_PW };
    TPMS_AUTH_COMMAND  *session_cmd_array[1] = { &session_cmd };
    TSS2_SYS_CMD_AUTHS  sessions_cmd         = {
        .cmdAuths      = session_cmd_array,
        .cmdAuthsCount = 1
    };
    /* response session info */
    TPMS_AUTH_RESPONSE  session_rsp          = { 0 };
    TPMS_AUTH_RESPONSE *session_rsp_array[1] = { &session_rsp };
    TSS2_SYS_RSP_AUTHS  sessions_rsp         = {
        .rspAuths      = session_rsp_array,
        .rspAuthsCount = 1
    };

    rc = create_primary_rsa_2048_aes_128_cfb (sapi_context, &primary_handle);
    if (rc != TSS2_RC_SUCCESS) {
        print_log ("failed to create primary: 0x%" PRIx32, rc);
        return rc;
    }

    rc = Tss2_Sys_EvictControl (sapi_context,
                                TPM_RH_OWNER,
                                primary_handle,
                                &sessions_cmd,
                                0x81000000,
                                &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        print_log ("failed to make key 0x%" PRIx32 " persistent: 0x%" PRIx32,
                   primary_handle, rc);
    }

    Tss2_Sys_FlushContext( sapi_context, 0x81000000 );
    Tss2_Sys_FlushContext( sapi_context, primary_handle );

    return rc;
}
