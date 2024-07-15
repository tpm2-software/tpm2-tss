/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <json.h>                // for json_object_object_get_ex, json_obje...
#include <stdbool.h>             // for bool, false, true
#include <stdio.h>               // for NULL, fopen, fprintf, fclose, fileno
#include <stdlib.h>              // for malloc, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>              // for strlen, strcmp
#include <unistd.h>              // for read

#include "test-fapi-policies.h"  // for policy_digests, _test_fapi_policy_po...
#include "test-fapi.h"           // for pcr_reset, ASSERT, ASSERT_SIZE, test...
#include "tss2_common.h"         // for TSS2_RC
#include "tss2_fapi.h"           // for Fapi_Delete, FAPI_CONTEXT, Fapi_Expo...

#define LOGMODULE test
#include "util/log.h"            // for LOG_ERROR, goto_if_error, SAFE_FREE

/** Check the digest values from result table for sha256 and sha384. */
static bool
check_policy(char *policy, policy_digests *digests) {
    json_object *jso = NULL;
    json_object *jso_digest_struct = NULL;
    json_object *jso_digest_list = NULL;
    json_object *jso_digest = NULL;
    const char *digest_str= NULL;
    bool check_sha256 = false;
    bool check_sha384 = false;
    int i, n;

    jso = json_tokener_parse(policy);
    if (!jso) {
        LOG_ERROR("JSON error in policy");
        goto error;
    }
    if (!json_object_object_get_ex(jso, "policyDigests", &jso_digest_list)) {
        LOG_ERROR("Policy error");
        goto error;
    }
    n = json_object_array_length(jso_digest_list);
    if (n > 0) {
        if (!digests->sha256 || !digests->sha384) {
            LOG_ERROR("Digest computation for %s should not be possible.", digests->path);
            goto error;
        }
    }
    /* verify that all hashes in policy (first param) match with digests (second param) */
    for (i = 0; i < n; i++) {
        jso_digest_struct = json_object_array_get_idx(jso_digest_list, i);
        if (!jso_digest_struct) {
            LOG_ERROR("Policy error");
            goto error;
        }
        if (!json_object_object_get_ex(jso_digest_struct, "digest", &jso_digest)) {
            LOG_ERROR("Policy error2");
            goto error;
        }

        digest_str = json_object_get_string(jso_digest);
        LOG_ERROR("Searching for hash: %s", json_object_get_string(jso_digest));
        if (strlen(digest_str) == 64 && strcmp(digest_str, digests->sha256) != 0)
            printf(" ");
        if (strlen(digest_str) == 64) {
            LOG_ERROR("%i - Digest SHA256:  %s", i, digests->sha256);
            LOG_INFO("Digest SHA256: %s", digests->sha256);
            if (strcmp(digest_str, digests->sha256) == 0) {
                LOG_ERROR(" -> sha256 pass");
                check_sha256 = true;
            }
        } else if  (strlen(digest_str) == 96) {
            LOG_ERROR("%i - Digest SHA384:  %s", i, digests->sha384);
            LOG_INFO("Digest SHA384: %s", digests->sha384);
            if (strcmp(digest_str, digests->sha384) == 0) {
                LOG_ERROR(" -> sha384 pass");
                check_sha384 = true;
            }
        } else {
            LOG_WARNING("%i - Hash alg not in result table.", i);
        }
        if (n > 0 && i == n - 1 && (!check_sha256 || !check_sha384))
            printf(" ");
    }
    json_object_put(jso);
    if (n > 0 && (!check_sha256 || !check_sha384)) {
        LOG_ERROR("Hash not found: %s", digest_str);
        LOG_ERROR("Policy check failed for: %s", digests->path);
        goto error;
    }
    return true;
 error:
    if (jso)
        json_object_put(jso);
    return false;
}

static char *
read_policy(FAPI_CONTEXT *context, char *policy_name)
{
    FILE *stream = NULL;
    long policy_size;
    char *json_policy = NULL;
    char policy_file[1024];

    if (snprintf(&policy_file[0], 1023, TOP_SOURCEDIR "/test/data/fapi/%s.json", policy_name) < 0)
        return NULL;

    stream = fopen(policy_file, "r");
    if (!stream) {
        LOG_ERROR("File %s does not exist", policy_file);
        return NULL;
    }
    fseek(stream, 0L, SEEK_END);
    policy_size = ftell(stream);
    fclose(stream);
    json_policy = malloc(policy_size + 1);
    stream = fopen(policy_file, "r");
    ssize_t ret = read(fileno(stream), json_policy, policy_size);
    if (ret != policy_size) {
        LOG_ERROR("IO error %s.", policy_file);
        return NULL;
    }
    json_policy[policy_size] = '\0';
    return json_policy;
}

/** Test the FAPI key signing with PolicyAuthorizeNV.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_Import()
 *  - Fapi_ExportPolicy()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_export_policy(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    size_t i;

    char *json_policy = NULL;
    char *policy = NULL;

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = pcr_reset(context, 16);
    goto_if_error(r, "Error pcr_reset", error);

    //for (i = 0; i < sizeof(_test_fapi_policy_policies) / sizeof(_test_fapi_policy_policies[0]); i++) {
    for (i = 25; i < 26; i++) {
        fprintf(stderr, "\nTest policy: %s\n",  _test_fapi_policy_policies[i].path);
        json_policy = read_policy(context, _test_fapi_policy_policies[i].path);
        if (!json_policy)
            goto error;

        r = Fapi_Import(context, _test_fapi_policy_policies[i].path, json_policy);
        goto_if_error(r, "Error Fapi_Import", error);

        policy = NULL;
        r = Fapi_ExportPolicy(context, _test_fapi_policy_policies[i].path, &policy);
        fprintf(stderr, "\nPolicy from policy file:\n%s\n%s\n", _test_fapi_policy_policies[i].path, policy);

        goto_if_error(r, "Error Fapi_ExportPolicy", error);
        ASSERT(policy != NULL);
        ASSERT(strlen(policy) > ASSERT_SIZE);
        if (!check_policy(policy, &_test_fapi_policy_policies[i])) {
            goto error;
        }

        SAFE_FREE(json_policy);
        SAFE_FREE(policy);
    }

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
    SAFE_FREE(json_policy);
    SAFE_FREE(policy);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *context)
{
    return test_fapi_export_policy(context);
}
