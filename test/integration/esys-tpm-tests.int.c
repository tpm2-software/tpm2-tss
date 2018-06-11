/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/* Test the ESAPI functions for TPM tests */
int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;

    esys_context->state = _ESYS_STATE_INIT;
    r = Esys_SelfTest(esys_context,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 0);
    goto_if_error(r, "Error SelfTest did fail", error);

	TPML_ALG alg_list = { .count = 1 , .algorithms = { TPM2_ALG_SHA1 }};
	TPML_ALG *toDoList;

    esys_context->state = _ESYS_STATE_INIT;
    r = Esys_IncrementalSelfTest(esys_context,
                                 ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &alg_list, &toDoList);
    goto_if_error(r, "Error IncrementalSelfTest did not fail", error);
    free(toDoList);

    TPM2B_MAX_BUFFER *outData;
    TPM2_RC testResult;

    esys_context->state = _ESYS_STATE_INIT;
    r = Esys_GetTestResult(esys_context,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           &outData, &testResult);
    goto_if_error(r, "Error GetTestResult did fail", error);
    free(outData);

    return 0;

 error:
    return 1;
}
