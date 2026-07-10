/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h> // for NULL, EXIT_FAILURE, EXIT_SUCCESS

#include "test-esys.h"       // for EXIT_SKIP, test_invoke_esys
#include "tss2_common.h"     // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_RESMGR_R...
#include "tss2_esys.h"       // for Esys_Free, Esys_FlushContext, ESYS_TR_NONE
#include "tss2_tpm2_types.h" // for TPM2_RC_COMMAND_CODE, TPM2B_ATTEST, TPM2B...

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_INFO, LOG_ERROR, LOG...

/** This test ensures that passing TPM_RH_NULL for a command handle
 *  that accepts TPMI_DH_OBJECT+ works correctly when the corresponding
 *  authorization session is TPM_RH_PW.
 *
 * Tested ESYS commands:
 *  - Esys_GetTime() (O)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */

int
test_esys_get_time(ESYS_CONTEXT *esys_context) {
    TSS2_RC r;
    int     failure_return = EXIT_FAILURE;

    TPM2B_ATTEST   *timeInfo = NULL;
    TPMT_SIGNATURE *signature = NULL;

    ESYS_TR         privacyAdminHandle = ESYS_TR_RH_ENDORSEMENT;
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    TPM2B_DATA      qualifyingData = { 0 };

    r = Esys_GetTime(esys_context, privacyAdminHandle, ESYS_TR_NONE, ESYS_TR_PASSWORD,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, &qualifyingData, &inScheme, &timeInfo,
                     &signature);
    if ((r == TPM2_RC_COMMAND_CODE) || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_GetTime not supported by TPM.");

        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error: GetTime", error);

    Esys_Free(timeInfo);
    Esys_Free(signature);
    return EXIT_SUCCESS;

error:

    Esys_Free(timeInfo);
    Esys_Free(signature);
    return failure_return;
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_get_time(esys_context);
}
