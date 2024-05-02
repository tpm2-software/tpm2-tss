/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>       // for NULL, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>       // for strcmp, strncmp

#include "test-fapi.h"    // for init_fapi, FAPI_PROFILE, pcr_reset, EXIT_SKIP
#include "tss2_common.h"  // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_FAPI_RC_AUTH...
#include "tss2_fapi.h"    // for Fapi_Provision, Fapi_Delete, Fapi_Finalize

#define LOGMODULE test
#include "util/log.h"     // for goto_if_error, UNUSED, LOG_ERROR, LOG_WARNING

#define PASSWORD "abc"

static TSS2_RC
auth_callback(
    char const *objectPath,
    char const *description,
    const char **auth,
    void *userData)
{
    UNUSED(description);
    UNUSED(userData);

    if (!objectPath) {
        return_error(TSS2_FAPI_RC_BAD_VALUE, "No path.");
    }

    *auth = PASSWORD;
    return TSS2_RC_SUCCESS;
}

/** Test the FAPI provisioning with passwords already set for endorsement and
 *  owner hierarchy.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_SetAuthCB()
 *  - Fapi_ChangeAuth()
 *  - Fapi_Delete()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_test_second_provisioning(FAPI_CONTEXT *context)
{
    TSS2_RC r;

    if (strncmp(FAPI_PROFILE, "P_RSA", 5) == 0) {
        LOG_WARNING("Default ECC profile needed for this test %s is used", FAPI_PROFILE);
        return EXIT_SKIP;
    }

    /* We need to reset the passwords again, in order to not brick physical TPMs */
    r = Fapi_Provision(context, PASSWORD, PASSWORD, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = pcr_reset(context, 16);
    goto_if_error(r, "Error pcr_reset", error);

    r = Fapi_SetAuthCB(context, auth_callback, NULL);
    goto_if_error(r, "Error SetPolicyAuthCallback", error);

    goto_if_error(r, "Error Fapi_NV_Undefine", error);

    Fapi_Finalize(&context);

    int rc = init_fapi("P_RSA2", &context);
    if (rc)
        goto error;

    /* Authentication should not work due to auth for hierarchy was set. */
    r = Fapi_Provision(context, NULL, NULL, NULL);

    if (r == TSS2_RC_SUCCESS) {
        goto_if_error(r, "Wrong authentication.", error);
    }
    if (r != TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN) {
        goto_if_error(r, "Wrong check auth value.", error);
    }

    /* Correct Provisioning with auth value for hierarchy from previous
       provisioning. The information whether a auth value is needed
       will be taken from hierarchy object of first provisioning. */
    r = Fapi_SetAuthCB(context, auth_callback, NULL);
    goto_if_error(r, "Error SetPolicyAuthCallback", error);

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    Fapi_Finalize(&context);
    rc = init_fapi("P_RSA2", &context);
    if (rc)
        goto error;

     /* Correct Provisioning with auth value for hierarchy from previous
       provisioning. Non information whether auth value is needed is
       available. */

    r = Fapi_SetAuthCB(context, auth_callback, NULL);
    goto_if_error(r, "Error SetPolicyAuthCallback", error);

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    /* We need to reset the passwords again, in order to not brick physical TPMs */
    r = Fapi_ChangeAuth(context, "/HS", NULL);
    goto_if_error(r, "Error Fapi_ChangeAuth", error);

    r = Fapi_ChangeAuth(context, "/HE", NULL);
    goto_if_error(r, "Error Fapi_ChangeAuth", error);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    Fapi_Finalize(&context);

    if (strcmp(FAPI_PROFILE, "P_ECC384") == 0) {
        rc = init_fapi("P_ECC_sh_eh_policy_sha384", &context);
    } else {
         rc = init_fapi("P_ECC_sh_eh_policy", &context);
    }

    if (rc)
        goto error;

    /* A policy will be assigned to owner and endorsement hierarchy. */

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    Fapi_Finalize(&context);
    if (strcmp(FAPI_PROFILE, "P_ECC") == 0) {
        rc = init_fapi("P_ECC", &context);
    } else if (strcmp(FAPI_PROFILE, "P_ECC384") == 0) {
        rc = init_fapi("P_ECC384", &context);
    } else if (strcmp(FAPI_PROFILE, "P_RSA3072") == 0) {
        rc = init_fapi("P_ECC384", &context);
    } else {
        LOG_ERROR("Profile %s not supported for this test!", FAPI_PROFILE);
    }

    if (rc)
        goto error;

    /* Owner and endorsement hierarchy will be authorized via policy and
       policy will be reset. */
    r = Fapi_Provision(context, NULL, NULL, NULL);

    goto_if_error(r, "Error Fapi_Provision", error);

    Fapi_Delete(context, "/");

    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_test_second_provisioning(fapi_context);
}
