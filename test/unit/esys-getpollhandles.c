/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>     // for uint32_t, uint64_t, uint8_t
#include <stdlib.h>       // for NULL, free, size_t, malloc
#include <string.h>       // for memcpy, memset

#include "../helper/cmocka_all.h"       // for assert_int_equal, CMUnitTest, assert_memory...
#include "tss2_common.h"  // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_TCTI_RC_BAD_...
#include "tss2_esys.h"    // for ESYS_CONTEXT, Esys_Finalize, Esys_GetPollHa...
#include "tss2_tcti.h"    // for TSS2_TCTI_CONTEXT, TSS2_TCTI_POLL_HANDLE

#define LOGMODULE tests
#include "util/log.h"

#define TCTI_FAKE_MAGIC 0x46414b4500000000ULL        /* 'FAKE\0' */
#define TCTI_FAKE_VERSION 0x1

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC(*finalize) (TSS2_TCTI_CONTEXT * tctiContext);
    TSS2_RC(*cancel) (TSS2_TCTI_CONTEXT * tctiContext);
    TSS2_RC(*getPollHandles) (TSS2_TCTI_CONTEXT * tctiContext,
                           TSS2_TCTI_POLL_HANDLE * handles,
                           size_t * num_handles);
    TSS2_RC(*setLocality) (TSS2_TCTI_CONTEXT * tctiContext, uint8_t locality);
} TSS2_TCTI_CONTEXT_FAKE;


TSS2_TCTI_POLL_HANDLE rev[] = {
    {.fd=66, .events=1, .revents=0},
    {.fd=99, .events=1, .revents=0}
};

static TSS2_RC
tcti_fake_getpollhandles(TSS2_TCTI_CONTEXT * tctiContext,
                         TSS2_TCTI_POLL_HANDLE * handles,
                         size_t * num_handles)
{
    (void) tctiContext;
    if (handles == NULL) {
        *num_handles = 2;
        return TSS2_RC_SUCCESS;
    }
    assert_int_equal(*num_handles, 2);
    memcpy(&handles[0], &rev[0], sizeof(rev));
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
tcti_fake_initialize(TSS2_TCTI_CONTEXT * tctiContext, size_t * contextSize)
{
    TSS2_TCTI_CONTEXT_FAKE *tcti_fake =
        (TSS2_TCTI_CONTEXT_FAKE *) tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_fake);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_fake, 0, sizeof(*tcti_fake));
    TSS2_TCTI_MAGIC(tctiContext) = TCTI_FAKE_MAGIC;
    TSS2_TCTI_VERSION(tctiContext) = TCTI_FAKE_VERSION;
    TSS2_TCTI_TRANSMIT(tctiContext) = (void*)1;
    TSS2_TCTI_RECEIVE(tctiContext) = (void*)1;
    TSS2_TCTI_FINALIZE(tctiContext) = NULL;
    TSS2_TCTI_CANCEL(tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES(tctiContext) = tcti_fake_getpollhandles;
    TSS2_TCTI_SET_LOCALITY(tctiContext) = NULL;

    return TSS2_RC_SUCCESS;
}


static int
setup(void **state)
{
    TSS2_RC r;
    ESYS_CONTEXT *ectx;
    size_t size = sizeof(TSS2_TCTI_CONTEXT_FAKE);
    TSS2_TCTI_CONTEXT *tcti = malloc(size);

    r = tcti_fake_initialize(tcti, &size);
    if (r)
        return (int)r;
    r = Esys_Initialize(&ectx, tcti, NULL);
    *state = (void *)ectx;
    return (int)r;
}

static int
teardown(void **state)
{
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(ectx, &tcti);
    Esys_Finalize(&ectx);
    free(tcti);
    return 0;
}

static void
test_GetPollHandles(void **state)
{
    TSS2_RC r;
    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *) * state;

    TSS2_TCTI_POLL_HANDLE *handles;
    size_t count;

    r = Esys_GetPollHandles(ectx, &handles, &count);
    assert_int_equal(r, TSS2_RC_SUCCESS);

    assert_int_equal(count, 2);
    assert_memory_equal((void*)&handles[0], (void*)&rev[0], sizeof(rev));
    free(handles);
}

int
main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_GetPollHandles, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
