/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
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
