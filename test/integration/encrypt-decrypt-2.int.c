#include <string.h>
#include <inttypes.h>

#include "log.h"
#include "sapi-util.h"
#include "test.h"

#define ENC_STR "test-data-test-data-test-data"

/*
 * This test is inteded to exercise the EncryptDecrypt2 command.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPM_HANDLE handle_parent, handle;
    TPM2B_MAX_BUFFER data_in = { 0 };
    TPM2B_MAX_BUFFER data_encrypted = TPM2B_MAX_BUFFER_INIT;
    TPM2B_MAX_BUFFER data_decrypted = TPM2B_MAX_BUFFER_INIT;

    data_in.t.size = strlen (ENC_STR);
    strcpy ((char*)data_in.t.buffer, ENC_STR);

    rc = create_primary_rsa_2048_aes_128_cfb (sapi_context, &handle_parent);
    if (rc != TSS2_RC_SUCCESS) {
        print_fail ("Failed to create primary RSA 2048 key: 0x%" PRIx32 "\n",
                    rc);
    }

    rc = create_aes_128_cfb (sapi_context, handle_parent, &handle);
    if (rc != TSS2_RC_SUCCESS) {
        print_fail ("Failed to create child AES 128 key: 0x%" PRIx32 "\n", rc);
    }

    print_log ("Encrypting data: \"%s\" with key handle: 0x%08" PRIx32,
               data_in.t.buffer, handle);
    rc = encrypt_2_cfb (sapi_context, handle, &data_in, &data_encrypted);
    if (rc != TSS2_RC_SUCCESS) {
        print_fail ("Failed to encrypt buffer: 0x%" PRIx32 "\n", rc);
    }

    rc = decrypt_2_cfb (sapi_context, handle, &data_encrypted, &data_decrypted);
    if (rc != TSS2_RC_SUCCESS) {
        print_fail ("Failed to encrypt buffer: 0x%" PRIx32 "\n", rc);
    }
    print_log ("Decrypted data: \"%s\" with key handle: 0x%08" PRIx32,
               data_decrypted.t.buffer, handle);

    if (strcmp ((char*)data_in.t.buffer, (char*)data_decrypted.t.buffer)) {
        print_fail ("Decrypt succeeded but decrypted data != to input data\n");
    }

    return 0;
}
