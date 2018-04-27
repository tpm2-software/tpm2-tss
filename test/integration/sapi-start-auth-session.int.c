/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ***********************************************************************/
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "tss2_sys.h"

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
