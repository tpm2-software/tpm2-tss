/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT sponsored by Infineon Technologies AG
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
 ******************************************************************************/

#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_esys.h"

#define LOGMODULE tests
#include "util/log.h"

#define TCTI_FAKE_MAGIC 0x46414b4500000000ULL        /* 'FAKE\0' */
#define TCTI_FAKE_VERSION 0x1

typedef TSS2_TCTI_CONTEXT_COMMON_V1 TSS2_TCTI_CONTEXT_FAKE;

void
tcti_fake_finalize(TSS2_TCTI_CONTEXT *tctiContext)
{
    (void)(tctiContext);
}

TSS2_RC
get_tcti_default(TSS2_TCTI_CONTEXT **tcti) {
    if (tcti == NULL)
        return TSS2_BASE_RC_GENERAL_FAILURE;

    /* This is to calm down scan-build */
    TSS2_TCTI_CONTEXT_FAKE **faketcti = (TSS2_TCTI_CONTEXT_FAKE **) tcti;

    *faketcti = calloc(1, sizeof(TSS2_TCTI_CONTEXT_FAKE));
    TSS2_TCTI_MAGIC(*faketcti) = TCTI_FAKE_MAGIC;
    TSS2_TCTI_VERSION(*faketcti) = TCTI_FAKE_VERSION;
    TSS2_TCTI_TRANSMIT(*faketcti) = (void*)1;
    TSS2_TCTI_RECEIVE(*faketcti) = (void*)1;
    TSS2_TCTI_FINALIZE(*faketcti) = tcti_fake_finalize;
    TSS2_TCTI_CANCEL(*faketcti) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES(*faketcti) = NULL;
    TSS2_TCTI_SET_LOCALITY(*faketcti) = NULL;

    return TSS2_RC_SUCCESS;
}

static void
test(void **state)
{
    TSS2_RC r;
    ESYS_CONTEXT *ectx;

    r = Esys_Initialize(&ectx, NULL, NULL);
    assert_int_equal(r, TSS2_RC_SUCCESS);

    Esys_Finalize(&ectx);

    assert_ptr_equal(ectx, NULL);
}

int
main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
