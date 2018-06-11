/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#include "test-esapi.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * Test the commands Esys_PCR_SetAuthValue and Esys_PCR_SetAuthPolicy.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

    /*
     * PCR register 20 belongs to the policy group and the auth value group.
     * PCRs of these groups can be used for SetAuthValue and SetAuthPolicy.
     */
    ESYS_TR  pcrHandle_handle = 20;

    TPM2B_DIGEST auth = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    r = Esys_PCR_SetAuthValue(
        esys_context,
        pcrHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &auth
        );
    goto_if_error(r, "Error: PCR_SetAuthValue", error);

    TPM2B_DIGEST authPolicy = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    r = Esys_PCR_SetAuthPolicy(
        esys_context,
        ESYS_TR_RH_PLATFORM,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &authPolicy,
        TPM2_ALG_SHA1,
        pcrHandle_handle);
    goto_if_error(r, "Error: PCR_SetAuthPolicy", error);

    return 0;

 error:
    return r;
}
