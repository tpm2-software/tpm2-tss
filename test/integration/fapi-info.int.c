/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>       // for NULL, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>       // for strlen

#include "tss2_common.h"  // for TSS2_RC
#include "tss2_fapi.h"    // for Fapi_GetInfo, FAPI_CONTEXT

#define LOGMODULE test
#include "test-fapi.h"    // for ASSERT, CHECK_JSON_FIELDS, ASSERT_SIZE, tes...
#include "util/log.h"     // for SAFE_FREE, LOG_INFO, goto_if_error

/** Test the FAPI functions for GetInfo.
 *
 * Tested FAPI commands:
 *  - Fapi_Provision()
 *  - Fapi_GetInfo()
 *  - Fapi_Delete()
 *
 * @param[in,out] context The FAPI_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_fapi_info(FAPI_CONTEXT *context)
{

    TSS2_RC r;
    char *info = NULL;

    r = Fapi_GetInfo(context, &info);
    goto_if_error(r, "Error Fapi_Provision", error);
    ASSERT(info != NULL);
    ASSERT(strlen(info) > ASSERT_SIZE);

    LOG_INFO("%s", info);

    char *fields_config[] =  { "fapi_config" };
    CHECK_JSON_FIELDS(info, fields_config, "", error);

    char *fields_info[] =  { "capabilities" };
    CHECK_JSON_FIELDS(info, fields_info, "", error);

    SAFE_FREE(info);
    return EXIT_SUCCESS;

error:
    SAFE_FREE(info);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    return test_fapi_info(fapi_context);
}
