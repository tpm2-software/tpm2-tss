/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2026, Fraunhofer SIT
 * All rights reserved.
 *******************************************************************************/

#include "util/aux_util.h"
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <assert.h>  // for assert
#include <stdbool.h> // for bool, false, true
#include <stdint.h>  // for uint8_t
#include <stdio.h>   // for NULL, fopen, fclose, fileno, fseek, ftell
#include <stdlib.h>  // for EXIT_FAILURE, malloc, EXIT_SUCCESS
#include <string.h>  // for strcmp, memcmp
#include <unistd.h>  // for read

#include "test-fapi.h"   // for pcr_reset, test_invoke_fapi
#include "tss2_common.h" // for TSS2_RC, TSS2_FAPI_RC_BAD_VALUE, TSS2_RC_SU...
#include "tss2_fapi.h"   // for Fapi_CreateNv, Fapi_Delete, Fapi_Import

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR, UNUSED, SAFE_FREE

#define INDEX_PASSWORD1 "abc"
#define INDEX_PASSWORD2 "def"
#define KEY_PASSWORD1   "foo"
#define KEY_PASSWORD2   "bar"
#define KEY_PASSWORD3   "baz"
#define KEY_PASSWORD4   "fum"
#define SIGN_TEMPLATE   "sign,noDa"
#define NV_SIZE         sizeof(TPMT_HA)

static bool cb_branch_called = false;
static bool cb_auth_called = false;
static bool written = false;

static uint8_t digest[32] = { 0xd2, 0xa8, 0x4f, 0x4b, 0x8b, 0x65, 0x09, 0x37, 0xec, 0x8f, 0x73,
                              0xcd, 0x8b, 0xe2, 0xc7, 0x4a, 0xdd, 0x5a, 0x91, 0x1b, 0xa6, 0x4d,
                              0xf2, 0x74, 0x58, 0xed, 0x82, 0x29, 0xda, 0x80, 0x4a, 0x26 };

static TSS2_RC
auth_callback(char const *objectPath, char const *description, const char **auth, void *userData) {
    UNUSED(description);
    UNUSED(userData);

    if (!objectPath) {
        return_error(TSS2_FAPI_RC_BAD_VALUE, "No path.");
    }

    if (strcmp(objectPath, "/nv/Owner/index-1") == 0)
        *auth = INDEX_PASSWORD1;
    else if (strcmp(objectPath, "/nv/Owner/index-2") == 0)
        *auth = INDEX_PASSWORD2;
    else if (strcmp(objectPath, "P_ECC/HS/SRK/key-1") == 0)
        *auth = KEY_PASSWORD1;
    else if (strcmp(objectPath, "P_ECC/HS/SRK/key-2") == 0)
        *auth = KEY_PASSWORD2;
    else if (strcmp(objectPath, "P_ECC/HS/SRK/key-3") == 0)
        *auth = KEY_PASSWORD3;
    else
        *auth = KEY_PASSWORD4;
    cb_auth_called = true;
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
branch_callback(char const  *objectPath,
                char const  *description,
                char const **branchNames,
                size_t       numBranches,
                size_t      *selectedBranch,
                void        *userData) {
    UNUSED(objectPath);
    UNUSED(description);
    UNUSED(userData);
    UNUSED(branchNames);

    if (numBranches != 2) {
        LOG_ERROR("Wrong number of branches");
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }

    if (!written)
        written = true;

    *selectedBranch = 0;
    cb_branch_called = true;
    return TSS2_RC_SUCCESS;
}

char *
read_file(const char *path) {
    ssize_t text_size;
    char   *content = NULL;
    FILE   *stream = fopen(path, "r");

    if (!stream) {
        LOG_ERROR("File %s does not exist", path);
        return NULL;
    }

    fseek(stream, 0L, SEEK_END);
    text_size = ftell(stream);
    fclose(stream);

    content = malloc(text_size + 1);
    if (!content) {
        LOG_ERROR("Could not allocate memory for the JSON policy");
        return NULL;
    }

    stream = fopen(path, "r");
    ssize_t ret = read(fileno(stream), content, text_size);
    if (ret != text_size) {
        LOG_ERROR("IO error %s.", path);
        free(content);
        fclose(stream);
        return NULL;
    }
    content[text_size] = '\0';
    fclose(stream);
    return content;
}

/** Test the FAPI for PolicyOr and PolicyAuthorizeNv in each branch, with nested PolicyOr and
 * PolicySecret as the authorized policies.
 *
 * The policy stored in each index referenced by that PolicyAuthorizeNv is a PolicyOr containing two
 * PolicyOr as branches, which then contain two PolicySecret each. Each PolicySecret references a
 * different key with a PolicyPassword and a different auth value.
 *
 * The NV indices storing the policy digest are accessed with a PolicyPassword.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_Import()
 *  - Fapi_CreateKey()
 *  - Fapi_CreateNv()
 *  - Fapi_WriteAuthorizeNv()
 *  - Fapi_SetBranchCB()
 *  - Fapi_SetAuthCB()
 *  - Fapi_Sign()
 *  - Fapi_VerifySignature()
 *  - Fapi_Delete()
 *  - Fapi_Free()
 *
 * Tested Policies:
 *  - PolicyOr
 *  - PolicySecret
 *  - PolicyAuthorizeNv
 *  - PolicyPassword
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_policy_complex(FAPI_CONTEXT *context) {
    TSS2_RC  r;
    char    *static_policy_name = "/policy/pol_or_authorize_nv";
    char    *static_policy_file = TOP_SOURCEDIR "/test/data/fapi/policy/pol_or_authorize_nv.json";
    char    *dyn_policy_name = "/policy/pol_or_or_secret";
    char    *dyn_policy_file = TOP_SOURCEDIR "/test/data/fapi/policy/pol_or_or_secret.json";
    char    *pw_policy_name = "/policy/password";
    char    *pw_policy_file = TOP_SOURCEDIR "/test/data/fapi/policy/pol_password.json";
    char    *static_json_policy = NULL;
    char    *dyn_json_policy = NULL;
    char    *pw_json_policy = NULL;
    uint8_t *signature = NULL;
    size_t   signature_size;

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = pcr_reset(context, 16);
    goto_if_error(r, "Error pcr_reset", error);

    static_json_policy = read_file(static_policy_file);
    goto_if_null(static_json_policy, "Error read static policy", TSS2_FAPI_RC_IO_ERROR, error);

    dyn_json_policy = read_file(dyn_policy_file);
    goto_if_null(dyn_json_policy, "Error read dyn policy", TSS2_FAPI_RC_IO_ERROR, error);

    pw_json_policy = read_file(pw_policy_file);
    goto_if_null(pw_json_policy, "Error read password policy", TSS2_FAPI_RC_IO_ERROR, error);

    r = Fapi_Import(context, static_policy_name, static_json_policy);
    goto_if_error(r, "Error Fapi_Import", error);

    r = Fapi_Import(context, dyn_policy_name, dyn_json_policy);
    goto_if_error(r, "Error Fapi_Import", error);

    r = Fapi_Import(context, pw_policy_name, pw_json_policy);
    goto_if_error(r, "Error Fapi_Import", error);

    r = Fapi_SetBranchCB(context, branch_callback, NULL);
    goto_if_error(r, "Error SetPolicybranchselectioncallback", error);

    r = Fapi_SetAuthCB(context, auth_callback, NULL);
    goto_if_error(r, "Error Fapi_SetAuthCB", error);

    r = Fapi_CreateNv(context, "/nv/Owner/index-1", "noda", NV_SIZE, pw_policy_name,
                      INDEX_PASSWORD1);
    goto_if_error(r, "Error Fapi_CreateNv", error);

    r = Fapi_CreateNv(context, "/nv/Owner/index-2", "noda", NV_SIZE, pw_policy_name,
                      INDEX_PASSWORD2);
    goto_if_error(r, "Error Fapi_CreateNv", error);

    r = Fapi_CreateKey(context, "/SRK/key-1", "", pw_policy_name, KEY_PASSWORD1);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_CreateKey(context, "/SRK/key-2", "", pw_policy_name, KEY_PASSWORD2);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_CreateKey(context, "/SRK/key-3", "", pw_policy_name, KEY_PASSWORD3);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_CreateKey(context, "/SRK/key-4", "", pw_policy_name, KEY_PASSWORD4);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_WriteAuthorizeNv(context, "/nv/Owner/index-1", dyn_policy_name);
    goto_if_error(r, "Error Fapi_WriteAuthorizeNv", error);

    r = Fapi_WriteAuthorizeNv(context, "/nv/Owner/index-2", dyn_policy_name);
    goto_if_error(r, "Error Fapi_WriteAuthorizeNv", error);

    r = Fapi_CreateKey(context, "/SRK/signing-key", "sign", static_policy_name, "");
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_Sign(context, "/SRK/signing-key", NULL, digest, sizeof(digest), &signature,
                  &signature_size, NULL, NULL);
    goto_if_error(r, "Fapi_Sign", error);

    r = Fapi_VerifySignature(context, "/SRK/signing-key", digest, sizeof(digest), signature,
                             signature_size);
    goto_if_error(r, "Fapi_VerifySignature", error);

    Fapi_Free(signature);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    SAFE_FREE(static_json_policy);
    SAFE_FREE(dyn_json_policy);
    SAFE_FREE(pw_json_policy);

    if (!cb_branch_called) {
        LOG_ERROR("Branch selection callback was not called.");
        return EXIT_FAILURE;
    }
    if (!cb_auth_called) {
        LOG_ERROR("Auth value callback was not called.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

error:
    Fapi_Free(signature);
    Fapi_Delete(context, "/");
    SAFE_FREE(static_json_policy);
    SAFE_FREE(dyn_json_policy);
    SAFE_FREE(pw_json_policy);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context) {
    return test_fapi_policy_complex(fapi_context);
}
