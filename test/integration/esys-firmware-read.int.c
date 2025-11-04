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
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_FirmwareRead, ESYS_C...
#include "tss2_tpm2_types.h"  // for TPM2_RC_COMMAND_CODE, TPM2B_MAX_BUFFER

#define LOGMODULE test
#include "util/log.h"         // for LOG_WARNING, goto_if_error

/** Test the ESYS function Esys_FirmwareRead.
 *
 * Tested ESYS commands:
 *  - Esys_FirmwareRead() (O)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */
int
test_esys_firmware_read(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    int failure_return = EXIT_FAILURE;

    UINT32 sequenceNumber = 0;
    TPM2B_MAX_BUFFER *fuData;
    r = Esys_FirmwareRead(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        sequenceNumber,
        &fuData);

    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_FirmwareRead not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error: FirmwareRead", error);

    return EXIT_SUCCESS;

 error:
    return failure_return;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_firmware_read(esys_context);
}
