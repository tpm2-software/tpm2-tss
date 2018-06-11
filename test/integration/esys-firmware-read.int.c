/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/* Test the ESAPI function Esys_FirmwareRead */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

    UINT32 sequenceNumber = 0;
    TPM2B_MAX_BUFFER *fuData;
    r = Esys_FirmwareRead(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        sequenceNumber,
        &fuData);

    if (r == TPM2_RC_COMMAND_CODE) {
        LOG_INFO("Command TPM2_FieldUpgradeData not supported by TPM.");
        r = 77; /* Skip */
        goto error;
    }
    goto_if_error(r, "Error: FirmwareRead", error);

    return 0;

 error:
    return r;
}
