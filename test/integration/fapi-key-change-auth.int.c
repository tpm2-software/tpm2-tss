/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "tss2_fapi.h"

#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

#define PASSWORD "abc"

static TSS2_RC
auth_callback(
    FAPI_CONTEXT *context,
    char const *description,
    char **auth,
    void *userData)
{
    (void)description;
    (void)userData;
    *auth = strdup(PASSWORD);
    return_if_null(*auth, "Out of memory.", TSS2_FAPI_RC_MEMORY);
    return TSS2_RC_SUCCESS;
}


/** Test the FAPI function for changing key authorizations.
 *
 * The setting of the authorization callback and usage of the
 * key with Fapi_Sign afterwards is also tested.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_CreateKey()
 *  - Fapi_ChangeAuth()
 *  - Fapi_SetAuthCB()
 *  - Fapi_Sign()
 *  - Fapi_Delete()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_key_change_auth(FAPI_CONTEXT *context)
{

    TSS2_RC r;
    uint8_t *signature = NULL;
    char    *publicKey = NULL;

    r = Fapi_Provision(context, NULL, NULL, NULL);

    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_CreateKey(context, "HS/SRK/mySignKey", "sign,noDa", "", NULL);
    goto_if_error(r, "Error Fapi_CreateKey", error);
    size_t signatureSize = 0;

    TPM2B_DIGEST digest = {
        .size = 20,
        .buffer = {
            0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
            0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f
        }
    };

    r = Fapi_ChangeAuth(context, "HS/SRK/mySignKey", PASSWORD);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_SetAuthCB(context, auth_callback, "");
    goto_if_error(r, "Error SetPolicyAuthCallback", error);

    r = Fapi_Sign(context, "HS/SRK/mySignKey", NULL,
                  &digest.buffer[0], digest.size, &signature, &signatureSize,
                  &publicKey, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    Fapi_Free(publicKey);

    r = Fapi_Delete(context, "/HS/SRK");
    goto_if_error(r, "Error Fapi_Delete", error);

    SAFE_FREE(signature);
    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/HS/SRK");
    SAFE_FREE(signature);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_key_change_auth(fapi_context);
}
