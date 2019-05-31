/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

/** This test is intended to test the ESAPI command  Esys_HASH.
 *
 * The test checks whether the TPM hash function can be used via the ESAPI.
 *
 * Tested ESAPI commands:
 *  - Esys_Hash() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */

int
test_esys_hash(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    TPM2B_MAX_BUFFER data = { .size = 20,
                              .buffer={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                       1, 2, 3, 4, 5, 6, 7, 8, 9}};
    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA1;
    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_OWNER;
    TPM2B_DIGEST *outHash;
    TPMT_TK_HASHCHECK *validation;

    r = Esys_Hash(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &data,
        hashAlg,
        hierarchy,
        &outHash,
        &validation);
    goto_if_error(r, "Error: Hash", error);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}

int
test_invoke_esapi(ESYS_CONTEXT * esys_context) {
    return test_esys_hash(esys_context);
}
