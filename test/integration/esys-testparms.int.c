/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/* Test the ESAPI function Esys_TestParms */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

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
                 .exponent = 65537,
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

    return 0;

 error:
    return 1;
}
