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
#ifndef TSS2_ERR_H_
#define TSS2_ERR_H_

#include <stdbool.h>

#include <sapi/tpm20.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The maximum size of a layer name.
 */
#define TSS2_ERR_LAYER_NAME_MAX  4

/**
 * The maximum size for layer specific error strings.
 */
#define TSS2_ERR_LAYER_ERROR_STR_MAX  512

/**
 * A custom error handler prototype.
 * @param rc
 *  The rc to decode with only the error bits set, ie no need to mask the
 *  layer bits out. Handlers will never be invoked with the error bits set
 *  to 0, as zero always indicates success.
 * @return
 *  An error string describing the rc. If the handler cannot determine
 *  a valid response, it can return NULL indicating that the framework
 *  should just print the raw hexidecimal value of the error field of
 *  a tpm2_err_layer_rc.
 *  Note that this WILL NOT BE FREED by the caller,
 *  i.e. static.
 */
typedef const char *(*Tss2_Error_Handler)(TSS2_RC rc);

bool
Tss2_Rc_Set_Handler(
    UINT8 layer,
    const char *name,
    Tss2_Error_Handler handler);

const char *
Tss2_Rc_StrError(
    TSS2_RC rc);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_ERR_H_ */
