/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>         // for NULL, calloc, free

#include "../helper/cmocka_all.h"         // for CMUnitTest, assert_int_equal, assert_ptr_...
#include "tss2_common.h"    // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_BASE_RC_GE...
#include "tss2_esys.h"      // for Esys_Finalize, Esys_Initialize, ESYS_CONTEXT
#include "tss2_tcti.h"      // for TSS2_TCTI_CONTEXT, TSS2_TCTI_CANCEL, TSS2...
#include "util/aux_util.h"  // for UNUSED

#define LOGMODULE tests
#include "util/log.h"

#define TCTI_FAKE_MAGIC 0x46414b4500000000ULL        /* 'FAKE\0' */
#define TCTI_FAKE_VERSION 0x1

typedef TSS2_TCTI_CONTEXT_COMMON_V1 TSS2_TCTI_CONTEXT_FAKE;

void
tcti_fake_finalize(TSS2_TCTI_CONTEXT *tctiContext)
{
    UNUSED(tctiContext);
}

TSS2_RC
__wrap_Tss2_TctiLdr_Initialize (const char *nameConf,
                                TSS2_TCTI_CONTEXT **tcti)
{
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

void
__wrap_Tss2_TctiLdr_Finalize (TSS2_TCTI_CONTEXT **tcti)
{
    free(*tcti);
    *tcti = NULL;
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
