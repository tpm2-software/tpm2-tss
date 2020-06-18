/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "tss2_fapi.h"

#include "test-fapi.h"
#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

#define PASSWORD NULL
#define SIGN_TEMPLATE  "sign,noDa"


/** Test the FAPI functions for PolicyPCR with key creation and usage.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_Import()
 *  - Fapi_CreateKey()
 *  - Fapi_Sign()
 *  - Fapi_ExportPolicy()
 *  - Fapi_Delete()
 *  - Fapi_Import()
 *  - Fapi_List()
 *
 * Tested Policies:
 *  - PolicyPcr (with currentPCRs set)
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_key_create_policy_pcr_sign(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    char *policy_name = "/policy/pol_pcr16_0";
    char *policy_pcr_read = "/policy/pol_pcr16_read";
    char *policy_file = TOP_SOURCEDIR "/test/data/fapi/policy/pol_pcr16_0.json";
    char *policy_pcr_read_file = TOP_SOURCEDIR "/test/data/fapi/policy/pol_pcr16_read.json";
    FILE *stream = NULL;
    char *json_policy = NULL;
    long policy_size;

    uint8_t *signature = NULL;
    char   *publicKey = NULL;
    char   *certificate = NULL;
    char *policy = NULL;
    char *path_list = NULL;

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = pcr_reset(context, 16);
    goto_if_error(r, "Error pcr_reset", error);

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

    r = Fapi_CreateKey(context, "/HS/SRK/mySignKey", SIGN_TEMPLATE,
                       policy_name, PASSWORD);
    goto_if_error(r, "Error Fapi_CreateKey", error);
    size_t signatureSize = 0;

    TPM2B_DIGEST digest = {
        .size = 20,
        .buffer = {
            0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
            0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f
        }
    };

    r = Fapi_Sign(context, "/HS/SRK/mySignKey", NULL,
                  &digest.buffer[0], digest.size, &signature, &signatureSize,
                  &publicKey, &certificate);
    goto_if_error(r, "Error Fapi_Sign", error);
    assert(signature != NULL);
    assert(publicKey != NULL);
    assert(certificate != NULL);

    r = Fapi_ExportPolicy(context, "HS/SRK/mySignKey", &policy);
    goto_if_error(r, "Error Fapi_ExportPolicy", error);
    assert(policy != NULL);
    fprintf(stderr, "\nPolicy from key:\n%s\n", policy);

    SAFE_FREE(policy);

    policy = NULL;
    r = Fapi_ExportPolicy(context, policy_name, &policy);
    goto_if_error(r, "Error Fapi_ExportPolicy", error);
    assert(policy != NULL);
    fprintf(stderr, "\nPolicy from policy file:\n%s\n", policy);

    /* Run test with current PCRs defined in policy */

    r = Fapi_Delete(context, "/HS/SRK/mySignKey");
    goto_if_error(r, "Error Fapi_Delete", error);

    fclose(stream);
    stream = fopen(policy_pcr_read_file, "r");
    if (!stream) {
        LOG_ERROR("File %s does not exist", policy_pcr_read_file);
        goto error;
    }
    fseek(stream, 0L, SEEK_END);
    policy_size = ftell(stream);
    fclose(stream);

    SAFE_FREE(json_policy);
    SAFE_FREE(signature);
    SAFE_FREE(publicKey);
    SAFE_FREE(certificate);
    SAFE_FREE(policy);
    SAFE_FREE(path_list);

    json_policy = malloc(policy_size + 1);
    goto_if_null(json_policy,
            "Could not allocate memory for the JSON policy",
            TSS2_FAPI_RC_MEMORY, error);
    stream = fopen(policy_pcr_read_file, "r");
    ret = read(fileno(stream), json_policy, policy_size);
    if (ret != policy_size) {
        LOG_ERROR("IO error %s.", policy_pcr_read_file);
        goto error;
    }
    json_policy[policy_size] = '\0';

    r = Fapi_Import(context, policy_pcr_read, json_policy);
    goto_if_error(r, "Error Fapi_Import", error);

    r = Fapi_CreateKey(context, "/HS/SRK/mySignKey", SIGN_TEMPLATE,
                       policy_pcr_read, PASSWORD);
    goto_if_error(r, "Error Fapi_CreateKey", error);
    signatureSize = 0;

    signature = NULL;
    publicKey = NULL;
    certificate = NULL;
    r = Fapi_Sign(context, "/HS/SRK/mySignKey", NULL,
                  &digest.buffer[0], digest.size, &signature, &signatureSize,
                  &publicKey, NULL);
    goto_if_error(r, "Error Fapi_Sign", error);
    assert(signature != NULL);
    assert(publicKey != NULL);
    assert(certificate != NULL);

    policy = NULL;
    r = Fapi_ExportPolicy(context, "HS/SRK/mySignKey", &policy);
    goto_if_error(r, "Error Fapi_ExportPolicy", error);
    assert(policy != NULL);
    fprintf(stderr, "\nPolicy from key:\n%s\n", policy);

    SAFE_FREE(policy);

    policy = NULL;
    r = Fapi_ExportPolicy(context, policy_pcr_read, &policy);
    goto_if_error(r, "Error Fapi_ExportPolicy", error);
    assert(policy != NULL);
    fprintf(stderr, "\nPolicy from policy file:\n%s\n", policy);

    r = Fapi_List(context, "", &path_list);
    goto_if_error(r, "Error Fapi_Delete", error);
    assert(path_list != NULL);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    fprintf(stderr, "\nPathList:\n%s\n", path_list);

    SAFE_FREE(json_policy);
    SAFE_FREE(signature);
    SAFE_FREE(publicKey);
    SAFE_FREE(certificate);
    SAFE_FREE(policy);
    SAFE_FREE(path_list);
    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
    SAFE_FREE(json_policy);
    SAFE_FREE(signature);
    SAFE_FREE(publicKey);
    SAFE_FREE(certificate);
    SAFE_FREE(policy);
    SAFE_FREE(path_list);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_key_create_policy_pcr_sign(fapi_context);
}
