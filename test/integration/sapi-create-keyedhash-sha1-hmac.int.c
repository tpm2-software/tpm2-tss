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
#include <stdlib.h>

#include "tss2_tpm2_types.h"

#include "inttypes.h"
#define LOGMODULE test
#include "util/log.h"
#include "sapi-util.h"
#include "test.h"

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC                  rc                = TPM2_RC_SUCCESS;
    TPM2_HANDLE              parent_handle     = 0;
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
    TSS2L_SYS_AUTH_COMMAND  sessions_cmd         = {
        .auths = {{ .sessionHandle = TPM2_RS_PW }},
        .count = 1
    };
    /* response session info */
    TSS2L_SYS_AUTH_RESPONSE  sessions_rsp         = {
        .auths = { 0 },
        .count = 0
    };

    rc = create_primary_rsa_2048_aes_128_cfb (sapi_context, &parent_handle);
    if (rc == TSS2_RC_SUCCESS) {
        LOG_INFO("primary created successfully: 0x%" PRIx32, parent_handle);
    } else {
        LOG_ERROR("CreatePrimary failed with 0x%" PRIx32, rc);
        return 99; /* fatal error */
    }

    inPublic.publicArea.nameAlg = TPM2_ALG_SHA1;
    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG_SHA1;

    LOG_INFO("Create keyedhash SHA1 HMAC");
    rc = TSS2_RETRY_EXP (Tss2_Sys_Create (sapi_context,
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
                                          &sessions_rsp));
    if (rc == TPM2_RC_SUCCESS) {
        LOG_INFO("success");
    } else {
        LOG_ERROR("Create FAILED! Response Code : 0x%x", rc);
        return 1;
    }

    rc = Tss2_Sys_FlushContext(sapi_context, parent_handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Tss2_Sys_FlushContext failed with 0x%"PRIx32, rc);
        return 99; /* fatal error */
    }

    return 0;
}
