/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"       // for FAPI_TEST_EK_CERT_LESS
#endif

#include <stdlib.h>       // for setenv, NULL, EXIT_FAILURE, EXIT_SUCCESS

#include "test-fapi.h"    // for EXIT_SKIP, test_invoke_fapi
#include "tss2_common.h"  // for TSS2_FAPI_RC_GENERAL_FAILURE, TSS2_RC
#include "tss2_fapi.h"    // for Fapi_Provision, FAPI_CONTEXT

#define LOGMODULE test
#include "util/log.h"     // for LOG_ERROR


/** Test the FAPI cleanup in an error case.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_test_provisioning_cert_error(FAPI_CONTEXT *context)
{
    TSS2_RC r;

#if !defined(SELF_SIGNED_CERTIFICATE) || defined(FAPI_TEST_EK_CERT_LESS)
    return EXIT_SKIP;
#endif

    setenv("FAPI_TEST_ROOT_CERT", "self", 1);
    setenv("FAPI_TEST_INT_CERT",  "./ca/root-ca/root-ca.cert.pem", 1);

    r = Fapi_Provision(context, NULL, NULL, NULL);

    if (r == TSS2_FAPI_RC_GENERAL_FAILURE)
        return EXIT_SUCCESS;

    LOG_ERROR("Test with self signed certificate did not fail.");
    return EXIT_FAILURE;

}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_test_provisioning_cert_error(fapi_context);
}
