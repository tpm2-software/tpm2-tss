/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for EXIT_FAILURE, EXIT_SUCCESS

#include "test-esys.h"        // for EXIT_SKIP, test_invoke_esys
#include "tss2_common.h"      // for TSS2_RC, TSS2_RESMGR_RC_LAYER, TSS2_RES...
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_FieldUpgradeData
#include "tss2_tpm2_types.h"  // for TPM2_RC_COMMAND_CODE, TPMT_HA, TPM2B_MA...

#define LOGMODULE test
#include "util/log.h"         // for LOG_WARNING, goto_if_error

/** Test the ESYS function Esys_FieldUpgradeStart and   Esys_FieldUpgradeData.
 *
 * Tested ESYS commands:
 *  - Esys_FieldUpgradeData() (O)
 *  - Esys_FieldUpgradeStart() (O)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */
int
test_esys_field_upgrade(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    int failure_return = EXIT_FAILURE;

    TPM2B_MAX_BUFFER fuData = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };
    TPMT_HA *nextDigest;
    TPMT_HA *firstDigest;

    r = Esys_FieldUpgradeData(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &fuData,
        &nextDigest,
        &firstDigest);
    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_FieldUpgradeData not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }

    goto_if_error(r, "Error: FieldUpgradeData", error);

    /* TODO test has to be adapted if FieldUpgrade commands are available */
    /*
    ESYS_TR authorization_handle = ESYS_TR_NONE;
    ESYS_TR keyHandle_handle = ESYS_TR_NONE;
    TPM2B_DIGEST fuDigest;
    TPMT_SIGNATURE manifestSignature;

    r = Esys_FieldUpgradeStart(
        esys_context,
        authorization_handle,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &fuDigest,
        &manifestSignature);
    goto_if_error(r, "Error: FieldUpgradeStart", error);
    */
    return EXIT_SUCCESS;

 error:
    return failure_return;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_field_upgrade(esys_context);
}
