/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h>           // for uint8_t
#include <stdio.h>            // for NULL, fopen, fclose, fileno, fseek, ftell
#include <stdlib.h>           // for malloc, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>           // for strstr, strcmp
#include <unistd.h>           // for read

#include "tss2_common.h"      // for BYTE, TSS2_FAPI_RC_MEMORY, TSS2_RC
#include "tss2_fapi.h"        // for Fapi_Delete, Fapi_CreateKey, Fapi_CreateNv
#include "tss2_tpm2_types.h"  // for TPM2B_DIGEST

#define LOGMODULE test
#include "test-fapi.h"        // for ASSERT, test_invoke_fapi
#include "util/log.h"         // for SAFE_FREE, goto_if_error, LOG_ERROR

#define SIGN_TEMPLATE  "sign,noDa"
#define PASSWORD NULL

#define NV_SIZE 4

/** Test the FAPI functions for NV writing and key usage.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_CreateKey()
 *  - Fapi_NvWrite()
 *  - Fapi_Import()
 *  - Fapi_Sign()
 *  - Fapi_Delete()
 *
 * Tested Policies:
 *  - PolicyNv
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_key_create_policy_nv_sign(FAPI_CONTEXT *context)
{
    TSS2_RC r;
#ifdef TPMIDX
    char *policy_name = "/policy/pol_nv";
#else
    char *policy_name = "/policy/pol_nv_tpm_idx";
#endif
    char *policy_file = TOP_SOURCEDIR "/test/data/fapi/policy/pol_nv.json";;
    FILE *stream = NULL;
    char *json_policy = NULL;
    uint8_t *signature = NULL;
    char    *publicKey = NULL;
    char    *certificate = NULL;
    long policy_size;

    char *nvPathOrdinary = "/nv/Owner/myNV";
    uint8_t data_nv[NV_SIZE] = { 1, 2, 3, 4 };
    char *pathList = NULL;
    size_t i;

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_CreateNv(context, nvPathOrdinary, "noda", 4,  "", "");
    goto_if_error(r, "Error Fapi_CreateNv", error);

    r = Fapi_NvWrite(context, nvPathOrdinary, &data_nv[0], NV_SIZE);
    goto_if_error(r, "Error Fapi_NvWrite", error);

    stream = fopen(policy_file, "r");
    if (!stream) {
        LOG_ERROR("File %s does not exist", policy_file);
        goto error;
    }
    fseek(stream, 0L, SEEK_END);
    policy_size = ftell(stream);
    fclose(stream);
    json_policy = malloc(policy_size + 1);
    goto_if_null(json_policy,
            "Could not allocate memory for the JSON policy",
            TSS2_FAPI_RC_MEMORY, error);
    stream = fopen(policy_file, "r");
    ssize_t ret = read(fileno(stream), json_policy, policy_size);
    if (ret != policy_size) {
        LOG_ERROR("IO error %s.", policy_file);
        goto error;
    }
    json_policy[policy_size] = '\0';

    r = Fapi_Import(context, policy_name, json_policy);
    goto_if_error(r, "Error Fapi_Import", error);

    r = Fapi_CreateKey(context, "HS/SRK/mySignKey", SIGN_TEMPLATE,
                       policy_name, PASSWORD);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_SetCertificate(context, "HS/SRK/mySignKey", "-----BEGIN "\
        "CERTIFICATE-----[...]-----END CERTIFICATE-----");
    goto_if_error(r, "Error Fapi_CreateKey", error);

    size_t signatureSize = 0;

    TPM2B_DIGEST digest = {
        .size = 32,
        .buffer = {
            0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
            0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        }
    };

    r = Fapi_Sign(context, "HS/SRK/mySignKey", NULL,
                  &digest.buffer[0], digest.size, &signature, &signatureSize,
                  &publicKey, &certificate);
    goto_if_error(r, "Error Fapi_Sign", error);
    ASSERT(signature != NULL);
    ASSERT(publicKey != NULL);
    ASSERT(certificate != NULL);
    ASSERT(strstr(publicKey, "BEGIN PUBLIC KEY"));
    ASSERT(strstr(certificate, "BEGIN CERTIFICATE"));

    /* Check all possible nv paths to get exactly nvPathOrdinary by Fapi_List. */
    char *path_check[] = {
        "/nv/Owner", "/nv/Owner/", nvPathOrdinary };

    for (i = 0; i < sizeof(path_check) / sizeof(path_check[0]); i++) {
        r = Fapi_List(context, path_check[i], &pathList);
        goto_if_error(r, "Error Fapi_List", error);
        ASSERT(strcmp(pathList, nvPathOrdinary) == 0);
        SAFE_FREE(pathList);
    }
    r = Fapi_Delete(context, nvPathOrdinary);
    goto_if_error(r, "Error Fapi_NV_Undefine", error);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    SAFE_FREE(signature);
    SAFE_FREE(publicKey);
    SAFE_FREE(certificate);
    SAFE_FREE(json_policy);
    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
    SAFE_FREE(signature);
    SAFE_FREE(publicKey);
    SAFE_FREE(certificate);
    SAFE_FREE(json_policy);
    SAFE_FREE(pathList);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_key_create_policy_nv_sign(fapi_context);
}
