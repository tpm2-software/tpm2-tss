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

#include "test-fapi.h"
#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"


/** Test the FAPI functions for sealing.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_CreateSeal()
 *  - Fapi_Unseal()
 *  - Fapi_Delete()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_unseal(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    size_t resultSize;
    uint8_t *result = NULL;

    TPM2B_DIGEST digest = {
        .size = 20,
        .buffer = {
            0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
            0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f
        }
    };

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_CreateSeal(context, "/HS/SRK/mySealObject", "noDa",
                        digest.size,
                        "", "",  &digest.buffer[0]);
    goto_if_error(r, "Error Fapi_CreateSeal", error);

    r = Fapi_Unseal(context, "/HS/SRK/mySealObject", &result,
                    &resultSize);
    goto_if_error(r, "Error Fapi_CreateSeal", error);

    r = Fapi_Delete(context, "/HS/SRK/mySealObject");
    goto_if_error(r, "Error Fapi_Delete", error);

    r = Fapi_Delete(context, "/HS/SRK");
    goto_if_error(r, "Error Fapi_Delete", error);

    if (resultSize != digest.size ||
            memcmp(result, &digest.buffer[0], resultSize) != 0) {
        LOG_ERROR("Error: unealed data not  equal to origin");
        goto error;
    }

    SAFE_FREE(result);
    return EXIT_SUCCESS;

error:
    SAFE_FREE(result);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_unseal(fapi_context);
}
