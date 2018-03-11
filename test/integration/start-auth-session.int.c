#include <inttypes.h>
#include <stdio.h>

#include "tpm20.h"

#define LOGMODULE test
#include "util/log.h"
#include "test.h"
/*
 * This is an incredibly simple test to create the most simple session
 * (which ends up being a trial policy) and then just tear it down.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPM2B_NONCE nonce_caller = {
        .size   = TPM2_SHA256_DIGEST_SIZE,
        .buffer = {
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
            }
    };
    TPM2B_NONCE nonce_tpm = {
        .size   = TPM2_SHA256_DIGEST_SIZE,
        .buffer = { 0 }
    };
    TPM2B_ENCRYPTED_SECRET encrypted_salt = { 0 };
    TPMI_SH_AUTH_SESSION   session_handle = 0;
    TPMT_SYM_DEF           symmetric      = { .algorithm = TPM2_ALG_NULL };

    LOG_INFO("StartAuthSession for TPM2_SE_POLICY (policy session)");
    rc = Tss2_Sys_StartAuthSession (sapi_context,
                                    TPM2_RH_NULL,     /* tpmKey */
                                    TPM2_RH_NULL,     /* bind */
                                    0,               /* cmdAuthsArray */
                                    &nonce_caller,   /* nonceCaller */
                                    &encrypted_salt, /* encryptedSalt */
                                    TPM2_SE_POLICY,   /* sessionType */
                                    &symmetric,      /* symmetric */
                                    TPM2_ALG_SHA256,  /* authHash */
                                    &session_handle, /* sessionHandle */
                                    &nonce_tpm,      /* nonceTPM */
                                    0                /* rspAuthsArray */
                                    );
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Tss2_Sys_StartAuthSession failed: 0x%" PRIx32, rc);
        exit(1);
    }
    LOG_INFO("StartAuthSession for TPM2_SE_POLICY success! Session handle: "
               "0x%" PRIx32, session_handle);
    /*
     * Clean out the session we've created. Would be nice if we didn't have
     * to do this ...
     */
    rc = Tss2_Sys_FlushContext (sapi_context, session_handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Tss2_Sys_FlushContext failed: 0x%" PRIx32, rc);
        exit(1);
    }
    LOG_INFO("Flushed context for session handle: 0x%" PRIx32 " success!",
               session_handle);

    return 0;
}
