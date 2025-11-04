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
#include "tss2_esys.h"        // for ESYS_TR_NONE, Esys_TestParms, ESYS_CONTEXT
#include "tss2_tpm2_types.h"  // for TPM2_ALG_AES, TPM2_ALG_CFB, TPM2_ALG_NULL

#define LOGMODULE test
#include "util/log.h"         // for goto_if_error

/** Test the ESYS function Esys_TestParms.
 *
 * Tested ESYS commands:
 *  - Esys_TestParms() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_testparms(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    TPMT_PUBLIC_PARMS parameters = {
        .type = TPM2_ALG_RSA,
        .parameters = {
            .rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                 .mode.aes = TPM2_ALG_CFB,
                 },
                 .scheme = {
                      .scheme =
                      TPM2_ALG_NULL,
                  },
             .keyBits = 2048,
                 .exponent = 0,
             }
        }
    };

    r = Esys_TestParms (
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &parameters
        );
    goto_if_error(r, "Error: TestParms", error);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_testparms(esys_context);
}
