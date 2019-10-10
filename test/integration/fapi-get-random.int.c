/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "tss2_fapi.h"

#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

/** Test the FAPI function FAPI_GetRandom.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_GetRandom()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_get_random(FAPI_CONTEXT *context)
{

    TSS2_RC r;
    /* Ensure that more than one call of Esys_GetRandom is necessary */
    size_t  bytesRequested = sizeof(TPMU_HA) + 10;
    uint8_t *randomBytes;

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_GetRandom(context, bytesRequested, &randomBytes);
    Fapi_Free(randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom FAILED! Response Code : 0x%x", r);
        goto error;
    }

    /* Cleanup */
    r = Fapi_Delete(context, "/HS/SRK");
    goto_if_error(r, "Error Fapi_Delete", error);

    return TSS2_RC_SUCCESS;

error:
    Fapi_Delete(context, "/HS/SRK");
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_get_random(fapi_context);
}
