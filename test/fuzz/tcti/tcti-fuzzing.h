/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 */

#ifndef TCTI_FUZZING_H
#define TCTI_FUZZING_H

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "tss2-tcti/tcti-common.h"
#include "tss2-sys/sysapi_util.h"

#define TCTI_FUZZING_MAGIC 0x66757a7a696e6700ULL

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    const uint8_t *data;
    size_t size;
} TSS2_TCTI_FUZZING_CONTEXT;

TSS2_TCTI_FUZZING_CONTEXT*
tcti_fuzzing_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx);

/*
 * Using the data and size fields of the fuzzing TCTI memcpy the data into the
 * structures given via va_list. Caller will pass the sysContext and number of
 * vararg arguments that follow.
 *
 * After that, for each argument, the caller must pass its size, a pointer to
 * the pointer/variable/structure and a bool indicating if the underlying arg
 * is a pointer.
 *
 * If yes, fuzz_fill might set the pointer to NULL.
 *
 * Example:
 *     TSS2L_SYS_AUTH_COMMAND const cmdAuthsArray = {0};
 *     TSS2L_SYS_AUTH_COMMAND const * cmdAuthsArray_ptr = &cmdAuthsArray;
 *     UINT16 bytesRequested = {0};
 *     UINT16 * bytesRequested_ptr = &bytesRequested;
 *     TPM2B_DIGEST randomBytes = {0};
 *     TPM2B_DIGEST * randomBytes_ptr = &randomBytes;
 *     TSS2L_SYS_AUTH_RESPONSE rspAuthsArray = {0};
 *     TSS2L_SYS_AUTH_RESPONSE * rspAuthsArray_ptr = &rspAuthsArray;
 *
 *     ret = fuzz_fill (
 *         sysContext,
 *         8,
 *         sizeof (cmdAuthsArray), &cmdAuthsArray_ptr, true,
 *         sizeof (bytesRequested), &bytesRequested_ptr, false,
 *         sizeof (randomBytes), &randomBytes_ptr, true,
 *         sizeof (rspAuthsArray), &rspAuthsArray_ptr, true
 *     );
 *     if (ret) {
 *         return ret;
 *     }
 *
 *     Tss2_Sys_GetRandom (
 *         sysContext,
 *         cmdAuthsArray_ptr,
 *         bytesRequested,
 *         randomBytes_ptr,
 *         rspAuthsArray_ptr
 *     );
 *
 * Note that fuzz_fill consumes the data, i.e. there will be less data left in
 * the tcti-fuzzing afterwards.
 *
 * Since we just dump the data into memory, this will assume that the data is
 * little endian for most platforms (as opposed to big endian which is how the)
 * data is sent over the wire.
 *
 */
static inline void
fuzz_fill (
        TSS2_SYS_CONTEXT *sysContext,
        size_t count,
        ...)
{
    va_list ap;
    size_t arg_len = 0;
    void **arg;
    int arg_is_pointer;
    TSS2_SYS_CONTEXT_BLOB *ctx = NULL;
    TSS2_TCTI_FUZZING_CONTEXT *tcti_fuzzing = NULL;
    bool set_pointer_null;

    ctx = syscontext_cast (sysContext);
    tcti_fuzzing = (TSS2_TCTI_FUZZING_CONTEXT *) ctx->tctiContext;

    va_start (ap, count);

    /* for each arg_len/arg pair */
    for (size_t i = 0; i < (count / 3); i++) {
        arg_len = va_arg (ap, size_t);
        arg = va_arg (ap, void **);
        arg_is_pointer = va_arg (ap, int);

        set_pointer_null = false;

        if (arg_is_pointer) {
            if (tcti_fuzzing->size < 1) {
                break;
            }
            set_pointer_null = tcti_fuzzing->data[0] == 0;
            tcti_fuzzing->data += 1;
            tcti_fuzzing->size -= 1;
        }
        if (set_pointer_null) {
            *arg = NULL;
        } else {
            if (tcti_fuzzing->size < arg_len) {
                break;
            }
            memcpy (*arg, tcti_fuzzing->data, arg_len);
            tcti_fuzzing->data += arg_len;
            tcti_fuzzing->size -= arg_len;
        }
    }

    va_end (ap);
}
#endif /* TCTI_FUZZING_H */
