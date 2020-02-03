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

#include "test-fapi.h"

#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

/** Test the FAPI functions for platform certificates.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_GetPlatformCertificates()
 *  - Fapi_Delete()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_platform_certificates(FAPI_CONTEXT *context)
{
    TSS2_RC r;
    uint8_t *certs = NULL;
    size_t certsSize = 0;

    r = Fapi_Provision(context, NULL, NULL, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_GetPlatformCertificates(context, &certs, &certsSize);
    if (r == TSS2_FAPI_RC_NO_CERT)
        goto skip;
    goto_if_error(r, "Error Fapi_GetPlatformCertificates", error);

    Fapi_Free(certs);

    /* Cleanup */
    r = Fapi_Delete(context, "/HS/SRK");
    goto_if_error(r, "Error Fapi_Delete", error);

    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/HS/SRK");
    return EXIT_FAILURE;

 skip:
    Fapi_Delete(context, "/HS/SRK");
    return EXIT_SKIP;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_platform_certificates(fapi_context);
}
