/*
 * Copyright (c) 2018, Intel Corporation
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
 */
#include "tcti/tcti_mssim.h"
#define LOGMODULE test
#include "log/log.h"
#include "sapi-util.h"
#include "test.h"


/* Test copmmand cancel functionality.
 * Create a primary object, which should pass. Then send a cancel on platform
 * command and try to create a primary object again - this should fial with
 * TPM_CANCEL rc. Then send a Cancel off command and try to create the object
 * for the third time. This time it should pass again. */

int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TPM2_HANDLE handle = 0;
    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_RC rc;
    TPM2B_SENSITIVE_CREATE  in_sensitive    = { 0 };
    TPM2B_PUBLIC            in_public       = { 0 };
    TPM2B_DATA              outside_info    = { 0 };
    TPML_PCR_SELECTION      creation_pcr    = { 0 };
    TPM2B_PUBLIC            out_public      = { 0 };
    TPM2B_CREATION_DATA     creation_data   = { 0 };
    TPM2B_DIGEST            creation_hash   = TPM2B_DIGEST_INIT;
    TPMT_TK_CREATION        creation_ticket = { 0 };
    TPM2B_NAME              name            = TPM2B_NAME_INIT;
    TSS2L_SYS_AUTH_COMMAND  sessions_cmd = {
        .auths = {{ .sessionHandle = TPM2_RS_PW }},
        .count = 1
    };
    TSS2L_SYS_AUTH_RESPONSE  sessions_rsp     = { 0 };

    in_public.publicArea.type = TPM2_ALG_RSA;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    in_public.publicArea.parameters.rsaDetail.keyBits = 2048;

    rc = Tss2_Sys_GetTctiContext(sapi_context, &tcti_context);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetTctiContext FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_DEBUG("GetTctiContext SUCCESS!");

    rc = create_primary_rsa_2048_aes_128_cfb (sapi_context, &handle);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_DEBUG("create_primary SUCCESS!");

    rc = Tss2_Sys_FlushContext(sapi_context, handle);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_DEBUG("FlushContext SUCCESS!");

    rc = tcti_platform_command(tcti_context, MS_SIM_CANCEL_ON);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("tcti_platform_command FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_DEBUG("tcti_platform_command CANCEL_ON SUCCESS!");

    rc = Tss2_Sys_CreatePrimary (sapi_context,
                                 TPM2_RH_OWNER,
                                 &sessions_cmd,
                                 &in_sensitive,
                                 &in_public,
                                 &outside_info,
                                 &creation_pcr,
                                 &handle,
                                 &out_public,
                                 &creation_data,
                                 &creation_hash,
                                 &creation_ticket,
                                 &name,
                                 &sessions_rsp);
    if (rc != TPM2_RC_CANCELED) {
        LOG_DEBUG("CreatePrimary returned unexpected rc 0x%x, expected 0x%x", rc,
                 TPM2_RC_CANCELED);
        exit(1);
    }
    LOG_DEBUG("create_primary returned rc cancelled!");

    rc = tcti_platform_command(tcti_context, MS_SIM_CANCEL_OFF);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_DEBUG("tcti_platform_command CANCEL_OFF SUCCESS!");

    rc = create_primary_rsa_2048_aes_128_cfb(sapi_context, &handle);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("create_primary FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_DEBUG("create_primary SUCCESS!");

    rc = Tss2_Sys_FlushContext(sapi_context, handle);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
    LOG_DEBUG("FlushContext SUCCESS!");
    return 0;
}
