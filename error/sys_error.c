//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <sapi/tpm20.h>

#include "sys_error.h"

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

const char *
sys_err_handler (
        TSS2_RC rc)
{
    (void) rc;

    /*
     * subtract 1 from the error number
     * before indexing into this array.
     *
     * Commented offsets are for the corresponding
     * error number *before* subtraction. Ie error
     * number 4 is at array index 3.
     */
    static const char *errors[] =	{
        // 1 - TSS2_BASE_RC_GENERAL_FAILURE
        "Catch all for all errors not otherwise specified",
        // 2 - TSS2_BASE_RC_NOT_IMPLEMENTED
        "If called functionality isn't implemented",
        // 3 - TSS2_BASE_RC_BAD_CONTEXT
        "A context structure is bad",
        // 4 - TSS2_BASE_RC_ABI_MISMATCH
        "Passed in ABI version doesn't match called module's ABI version",
        // 5 - TSS2_BASE_RC_BAD_REFERENCE
        "A pointer is NULL that isn't allowed to be NULL.",
        // 6 - TSS2_BASE_RC_INSUFFICIENT_BUFFER
        "A buffer isn't large enough",
        // 7 - TSS2_BASE_RC_BAD_SEQUENCE
        "Function called in the wrong order",
        // 8 - TSS2_BASE_RC_NO_CONNECTION
        "Fails to connect to next lower layer",
        // 9 - TSS2_BASE_RC_TRY_AGAIN
        "Operation timed out; function must be called again to be completed",
        // 10 - TSS2_BASE_RC_IO_ERROR
        "IO failure",
        // 11 - TSS2_BASE_RC_BAD_VALUE
        "A parameter has a bad value",
        // 12 - TSS2_BASE_RC_NOT_PERMITTED
        "Operation not permitted.",
        // 13 - TSS2_BASE_RC_INVALID_SESSIONS
        "Session structures were sent, but command doesn't use them or doesn't"
        " use the specified number of them",
        // 14 - TSS2_BASE_RC_NO_DECRYPT_PARAM
        "If function called that uses decrypt parameter, but command doesn't"
        " support decrypt parameter.",
        // 15 - TSS2_BASE_RC_NO_ENCRYPT_PARAM
        "If function called that uses encrypt parameter, but command doesn't"
        " support decrypt parameter.",
        // 16 - TSS2_BASE_RC_BAD_SIZE
        "If size of a parameter is incorrect",
        // 17 - TSS2_BASE_RC_MALFORMED_RESPONSE
        "Response is malformed",
        // 18 - TSS2_BASE_RC_INSUFFICIENT_CONTEXT
        "Context not large enough",
        // 19 - TSS2_BASE_RC_INSUFFICIENT_RESPONSE
        "Response is not long enough",
        // 20 - TSS2_BASE_RC_INCOMPATIBLE_TCTI
        "Unknown or unusable TCTI version",
        // 21 - TSS2_BASE_RC_NOT_SUPPORTED
        "Functionality not supported",
        // 22 - TSS2_BASE_RC_BAD_TCTI_STRUCTURE
        "TCTI context is bad"
  };

    return (rc - 1u < ARRAY_LEN(errors)) ? errors[rc - 1u] : NULL;
}
