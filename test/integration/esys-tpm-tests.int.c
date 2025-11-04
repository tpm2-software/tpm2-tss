/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>           // for free, EXIT_FAILURE, EXIT_SUCCESS

#include "esys_int.h"         // for ESYS_CONTEXT, _ESYS_STATE_INIT
#include "tss2_common.h"      // for TSS2_RC
#include "tss2_esys.h"        // for ESYS_TR_NONE, ESYS_CONTEXT, Esys_GetTes...
#include "tss2_tpm2_types.h"  // for TPML_ALG, TPM2B_MAX_BUFFER, TPM2_ALG_SH...

#define LOGMODULE test
#include "util/log.h"         // for goto_if_error

/** Test the ESYS functions for TPM tests.
 *
 * Tested ESYS commands:
 *  - Esys_GetTestResult() (M)
 *  - Esys_IncrementalSelfTest() (M)
 *  - Esys_SelfTest() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SUCCESS
 */
int
test_esys_tpm_tests(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    esys_context->state = ESYS_STATE_INIT;
    r = Esys_SelfTest(esys_context,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 0);
    goto_if_error(r, "Error SelfTest did fail", error);

    TPML_ALG alg_list = { .count = 1 , .algorithms = { TPM2_ALG_SHA256 }};
    TPML_ALG *toDoList;

    esys_context->state = ESYS_STATE_INIT;
    r = Esys_IncrementalSelfTest(esys_context,
                                 ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &alg_list, &toDoList);
    goto_if_error(r, "Error IncrementalSelfTest did not fail", error);
    free(toDoList);

    TPM2B_MAX_BUFFER *outData;
    TPM2_RC testResult;

    esys_context->state = ESYS_STATE_INIT;
    r = Esys_GetTestResult(esys_context,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           &outData, &testResult);
    goto_if_error(r, "Error GetTestResult did fail", error);
    free(outData);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_tpm_tests(esys_context);
}
