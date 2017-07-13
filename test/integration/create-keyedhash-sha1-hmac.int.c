#include "inttypes.h"
#include "log.h"
#include "sapi-util.h"
#include "test.h"

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TPM_RC                  rc                = TPM_RC_SUCCESS;
    TPM_HANDLE              parent_handle     = 0;
    TPM2B_SENSITIVE_CREATE  inSensitive       = { 0 };
    TPM2B_DATA              outsideInfo       = { 0 };
    TPML_PCR_SELECTION      creationPCR       = { 0 };

    TPM2B_PRIVATE       outPrivate             = TPM2B_PRIVATE_INIT;
    TPM2B_PUBLIC        inPublic               = { 0 };
    TPM2B_PUBLIC        outPublic              = { 0 };
    TPM2B_CREATION_DATA creationData           = { 0 };
    TPM2B_DIGEST        creationHash           = TPM2B_DIGEST_INIT;
    TPMT_TK_CREATION    creationTicket         = { 0 };

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

    rc = create_primary_rsa_2048_aes_128_cfb (sapi_context, &parent_handle);
    if (rc == TSS2_RC_SUCCESS) {
        print_log ("primary created successfully: 0x%" PRIx32, parent_handle);
    } else {
       return rc;
    }

    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.objectAttributes.sign = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA1;

    print_log ("Create keyedhash SHA1 HMAC");
    rc = Tss2_Sys_Create (sapi_context,
                          parent_handle,
                          &sessions_cmd,
                          &inSensitive,
                          &inPublic,
                          &outsideInfo,
                          &creationPCR,
                          &outPrivate,
                          &outPublic,
                          &creationData,
                          &creationHash,
                          &creationTicket,
                          &sessions_rsp);
    if (rc == TPM_RC_SUCCESS) {
        print_log ("success");
    } else {
        print_fail ("Create FAILED! Response Code : 0x%x", rc);
    }

    return rc;
}
