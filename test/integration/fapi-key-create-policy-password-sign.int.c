/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "tss2_fapi.h"
#include "fapi_util.h"
#include "fapi_int.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

#define PASSWORD "abc"

TSS2_RC
auth_callback(
    FAPI_CONTEXT *context,
    char const *description,
    char **auth,
    void *userData)
{
    (void)description;
    (void)userData;
    *auth = strdup(PASSWORD);
    return TSS2_RC_SUCCESS;
}
#define SIGN_TEMPLATE  "T_RSA_SIGN"
#define PROFILE "P_RSA"
#define PROFILE_DIR  ""


/** Test the FAPI functions for key creation and usage.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_Key_Create()
 *  - Fapi_Key_Sign()
 *  - Fapi_Entity_Delete()
 *  - Fapi_Entities_List()
 *
 * @param[in,out] esys_context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_key_create(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    char* policy_name = "policies/pol_password";
    char* policy_file = NULL;
    FILE *stream = NULL;
    char *json_policy = NULL;
    long policy_size;

    r = Fapi_Provision(context, PROFILE, NULL, NULL, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = ifapi_asprintf(&policy_file, "%s/%s.json", context->config.profile_dir,
                       policy_name);
    goto_if_error(r, "Create file name", error);

    r = Fapi_PCR_Reset(context, 16);
    goto_if_error(r, "Reset PCR 16", error);

    stream = fopen(policy_file, "r");
    if (!stream) {
        LOG_ERROR("File %s does not exist", policy_file);
        goto error;
    }
    fseek(stream, 0L, SEEK_END);
    policy_size = ftell(stream);
    fclose(stream);
    json_policy = malloc(policy_size + 1);
    stream = fopen(policy_file, "r");
    ssize_t ret = read(fileno(stream), json_policy, policy_size);
    if (ret != policy_size) {
         LOG_ERROR("IO error %s.", policy_file);
         goto error;
    }
    json_policy[policy_size] = '\0';

    r = Fapi_PolicyImport(context, policy_name, json_policy);
    goto_if_error(r, "Error Fapi_Entities_List", error);

    r = Fapi_Key_Create(context, PROFILE_DIR "HS/SNK/mySignKey", SIGN_TEMPLATE,
                        policy_name, PASSWORD);
    goto_if_error(r, "Error Fapi_Key_Create", error);
    size_t signatureSize = 0;
    size_t publicKeySize = 0;
    size_t certificateSize = 0;

    TPM2B_DIGEST digest = {
        .size = 20,
        .buffer = { 0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
                    0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f }
    };

    uint8_t *signature;
    uint8_t *publicKey;

    r = Fapi_SetPolicyAuthCallback(context, auth_callback, "");
    goto_if_error(r, "Error SetPolicyAuthCallback", error);

    r = Fapi_Key_Sign(context, PROFILE_DIR "HS/SNK/mySignKey",
                      &digest.buffer[0], digest.size, &signature, &signatureSize,
                      &publicKey, &publicKeySize, NULL, &certificateSize);
    goto_if_error(r, "Error Fapi_Key_Sign", error);

    r = Fapi_Entity_Delete(context, PROFILE "/HE/EK");
    goto_if_error(r, "Error Fapi_Entity_Delete", error);

    size_t numPaths;
    char  **pathlist;

    r = Fapi_Entities_List(context, PROFILE "/", &pathlist ,&numPaths);
    goto_if_error(r, "Error Fapi_Entities_List", error);

    /* The two storage keys should remain */
    if (numPaths != 2) {
        LOG_ERROR("Wrong number of objects in key store");
        goto error;
    }

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT * fapi_context) {
    return test_fapi_key_create(fapi_context);
}
