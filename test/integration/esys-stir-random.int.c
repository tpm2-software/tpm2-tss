/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for EXIT_FAILURE, EXIT_SUCCESS

#include "tss2_common.h"      // for TSS2_RC
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_StirRandom, ESYS_CON...
#include "tss2_tpm2_types.h"  // for TPM2B_SENSITIVE_DATA

#define LOGMODULE test
#include "util/log.h"         // for goto_if_error

/** Test the ESYS function Esys_StirRandom.
 *
 * Tested ESYS commands:
 *  - Esys_StirRandom() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_stir_random(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    TPM2B_SENSITIVE_DATA inData  = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    r = Esys_StirRandom(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inData);
    goto_if_error(r, "Error: StirRandom", error);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_stir_random(esys_context);
}
