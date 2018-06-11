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
#include <stdlib.h>
#include <string.h>

#define LOGMODULE test
#include "util/log.h"
#include "sapi-util.h"
#include "test.h"

#define ENC_STR "test-data-test-data-test-data"

/*
 * This test is intended to exercise the EncryptDecrypt2 command.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPM2_HANDLE handle_parent, handle;
    TPM2B_MAX_BUFFER data_in = { 0 };
    TPM2B_MAX_BUFFER data_encrypted = TPM2B_MAX_BUFFER_INIT;
    TPM2B_MAX_BUFFER data_decrypted = TPM2B_MAX_BUFFER_INIT;

    data_in.size = strlen (ENC_STR);
    strcpy ((char*)data_in.buffer, ENC_STR);

    rc = create_primary_rsa_2048_aes_128_cfb (sapi_context, &handle_parent);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to create primary RSA 2048 key: 0x%" PRIx32 "",
                    rc);
        exit(1);
    }

    rc = create_aes_128_cfb (sapi_context, handle_parent, &handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to create child AES 128 key: 0x%" PRIx32 "", rc);
        exit(1);
    }

    LOG_INFO("Encrypting data: \"%s\" with key handle: 0x%08" PRIx32,
               data_in.buffer, handle);
    rc = tpm_encrypt_2_cfb (sapi_context, handle, &data_in, &data_encrypted);

    if (rc == TPM2_RC_COMMAND_CODE) {
        LOG_WARNING("Encrypt/Decrypt 2 not supported by TPM");
        rc = Tss2_Sys_FlushContext(sapi_context, handle_parent);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR("Tss2_Sys_FlushContext failed with 0x%"PRIx32, rc);
            return 99; /* fatal error */
        }
        rc = Tss2_Sys_FlushContext(sapi_context, handle);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR("Tss2_Sys_FlushContext failed with 0x%"PRIx32, rc);
            return 99; /* fatal error */
        }
        return 77; /* skip */
    }

    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to encrypt buffer: 0x%" PRIx32 "", rc);
        exit(1);
    }

    rc = tpm_decrypt_2_cfb (sapi_context, handle, &data_encrypted, &data_decrypted);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Failed to encrypt buffer: 0x%" PRIx32 "", rc);
        exit(1);
    }
    LOG_INFO("Decrypted data: \"%s\" with key handle: 0x%08" PRIx32,
               data_decrypted.buffer, handle);

    if (strcmp ((char*)data_in.buffer, (char*)data_decrypted.buffer)) {
        LOG_ERROR("Decrypt succeeded but decrypted data != to input data");
        exit(1);
    }

    rc = Tss2_Sys_FlushContext(sapi_context, handle_parent);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Tss2_Sys_FlushContext failed with 0x%"PRIx32, rc);
        return 99; /* fatal error */
    }
    rc = Tss2_Sys_FlushContext(sapi_context, handle);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Tss2_Sys_FlushContext failed with 0x%"PRIx32, rc);
        return 99; /* fatal error */
    }

    return 0;
}
