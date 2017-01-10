#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"
#include "sysapi_util.h"
/**
 * This program contains integration test for asymetric encrypt and
 * decrypt use case that has SAPIs Tss2_Sys_CreatePrimary,
 * Tss2_Sys_Create, Tss2_Sys_Load, Tss2_Sys_RSA_Encrypt and
 * Tss2_Sys_RSA_Decrypt. First, the program creates the object and load
 * it in TPM. Then, it performs encryption based on the loaded
 * object. The object will be verified if it is encrypted.
 * If the verification is passed, it performs decryption and the
 * program will check if the decrypted value is the same as
 * the value before encryption.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPM2B_SENSITIVE_CREATE  in_sensitive;
    TPM2B_PUBLIC            in_public;
    TPM2B_DATA              outside_info = {{0,}};
    TPML_PCR_SELECTION      creation_pcr;
    TPM2B_NAME name = {{sizeof(TPM2B_NAME)-2,}};
    TPM2B_PRIVATE out_private = {{sizeof(TPM2B_PRIVATE)-2,}};
    TPM2B_PUBLIC out_public = {{0,}};
    TPM2B_CREATION_DATA creation_data = {{0,}};
    TPM2B_DIGEST creation_hash = {{sizeof(TPM2B_DIGEST)-2,}};
    TPMT_TK_CREATION creation_ticket = {0,};
    TPM_HANDLE loaded_sym_handle;
    TPM_HANDLE sym_handle;
    const char message[] = "my message";
    TPMT_RSA_DECRYPT in_scheme;
    TPM2B_PUBLIC_KEY_RSA input_message = {{sizeof(TPM2B_PUBLIC_KEY_RSA)-2,}};
    TPM2B_PUBLIC_KEY_RSA output_message = {{sizeof(TPM2B_PUBLIC_KEY_RSA)-2,}};
    TPM2B_PUBLIC_KEY_RSA output_data = {{sizeof(TPM2B_PUBLIC_KEY_RSA)-2,}};

    TPMS_AUTH_RESPONSE session_data_out;
    TPMS_AUTH_COMMAND session_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    session_data_array[0] = &session_data;
    session_data_out_array[0] = &session_data_out;
    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];
    sessions_data_out.rspAuthsCount = 1;
    session_data.sessionHandle = TPM_RS_PW;
    session_data.nonce.t.size = 0;
    session_data.hmac.t.size = 0;
    *((UINT8 *)((void *)&session_data.sessionAttributes)) = 0;
    sessions_data.cmdAuthsCount = 1;
    sessions_data.cmdAuths[0] = &session_data;

    in_sensitive.t.size =0;
    in_sensitive.t.sensitive.userAuth.t.size = 0;
    in_sensitive.t.sensitive.data.t.size = 0;

    in_public.t.publicArea.type = TPM_ALG_RSA;
    in_public.t.publicArea.nameAlg = TPM_ALG_SHA256;
    *(UINT32 *)&(in_public.t.publicArea.objectAttributes) = 0;
    in_public.t.publicArea.objectAttributes.restricted = 1;
    in_public.t.publicArea.objectAttributes.userWithAuth = 1;
    in_public.t.publicArea.objectAttributes.decrypt = 1;
    in_public.t.publicArea.objectAttributes.fixedTPM = 1;
    in_public.t.publicArea.objectAttributes.fixedParent = 1;
    in_public.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    in_public.t.publicArea.authPolicy.t.size = 0;

    in_public.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    in_public.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    in_public.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    in_public.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    in_public.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    in_public.t.publicArea.parameters.rsaDetail.exponent = 0;

    in_public.t.publicArea.unique.rsa.t.size = 0;

    outside_info.t.size = 0;
    creation_pcr.count = 0;
    out_public.t.size = 0;
    creation_data.t.size = 0;

    print_log("Asymmetric Encryption and Decryption Tests started.");
    rc = Tss2_Sys_CreatePrimary(sapi_context, TPM_RH_OWNER, &sessions_data, &in_sensitive, &in_public, &outside_info, &creation_pcr, &sym_handle, &out_public, &creation_data, &creation_hash, &creation_ticket, &name, &sessions_data_out);
    if (rc != TPM_RC_SUCCESS)
        print_fail("CreatePrimary FAILED! Response Code : 0x%x", rc);
    print_log("New key successfully created.  Handle: 0x%8.8x\n", sym_handle);

    in_public.t.publicArea.type = TPM_ALG_RSA;
    in_public.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    in_public.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    in_public.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    in_public.t.publicArea.parameters.rsaDetail.exponent = 0;
    in_public.t.publicArea.unique.rsa.t.size = 0;

    // First clear attributes bit field.
    *(UINT32 *)&(in_public.t.publicArea.objectAttributes) = 0;
    in_public.t.publicArea.objectAttributes.restricted = 0;
    in_public.t.publicArea.objectAttributes.userWithAuth = 1;
    in_public.t.publicArea.objectAttributes.decrypt = 1;
    in_public.t.publicArea.objectAttributes.sign = 1;
    in_public.t.publicArea.objectAttributes.fixedTPM = 1;
    in_public.t.publicArea.objectAttributes.fixedParent = 1;
    in_public.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    outside_info.t.size = 0;
    out_public.t.size = 0;
    creation_data.t.size = 0;
    session_data.hmac.t.size = 0;

    rc = Tss2_Sys_Create(sapi_context, sym_handle, &sessions_data, &in_sensitive, &in_public, &outside_info, &creation_pcr, &out_private, &out_public, &creation_data, &creation_hash, &creation_ticket, &sessions_data_out);
    if (rc != TPM_RC_SUCCESS)
        print_fail("Create FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_Load(sapi_context, sym_handle, &sessions_data, &out_private, &out_public, &loaded_sym_handle, &name, &sessions_data_out);
    if (rc != TPM_RC_SUCCESS)
        print_fail("Load FAILED! Response Code : 0x%x", rc);
    print_log( "Loaded key handle:  %8.8x\n", loaded_sym_handle );

    input_message.t.size = strlen(message);
    memcpy(input_message.t.buffer, message, input_message.t.size);
    in_scheme.scheme = TPM_ALG_RSAES;
    outside_info.t.size = 0;
    rc = Tss2_Sys_RSA_Encrypt(sapi_context, loaded_sym_handle, 0, &input_message, &in_scheme, &outside_info, &output_data, 0);
    if(rc != TPM_RC_SUCCESS)
        print_fail("RSA_Encrypt FAILED! Response Code : 0x%x", rc);
    print_log("Encrypt successed.");

    rc = Tss2_Sys_RSA_Decrypt(sapi_context, loaded_sym_handle, &sessions_data, &output_data, &in_scheme, &outside_info, &output_message, &sessions_data_out);
    if(rc != TPM_RC_SUCCESS)
        print_fail("RSA_Decrypt FAILED! Response Code : 0x%x", rc);
    print_log("Decrypt successed.");

    print_log("Asymmetric Encryption and Decryption Test Passed!");
    return 0;
}


