/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2018-2019, Intel Corporation
 */

#include <inttypes.h>
#if defined(__linux__)
#include <linux/limits.h>
#else
#include <limits.h>
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_tcti.h"
#include "tss2_tctildr.h"

#include "tss2-tcti/tctildr.h"
#include "tss2-tcti/tcti-common.h"

#define TEST_MAGIC 0x1234321
#define TEST_VERSION 3

#define TEST_TCTI_HANDLE (TSS2_TCTI_LIBRARY_HANDLE)0x9827635
#define TEST_INIT_RC 0x57648
#define TEST_SIZE_MAGIC 0x463830
void*
__real_calloc (size_t nmemb,
               size_t size);
void*
__wrap_calloc (size_t nmemb,
               size_t size)
{
    if (size == TEST_SIZE_MAGIC || size == sizeof (TSS2_TCTILDR_CONTEXT)) {
        void *tmp = mock_type (void*);
        return tmp;
    }
    return __real_calloc (nmemb, size);
}
/* used as the 'internal' TCTI context */
static TSS2_TCTI_CONTEXT_COMMON_V2 v2_ctx;
static TSS2_TCTILDR_CONTEXT tctildr_ctx;
void
__real_free (void *ptr);
void
__wrap_free (void *ptr)
{
    if (ptr == &v2_ctx || ptr == &tctildr_ctx) {
        return;
    }
    __real_free (ptr);
}
#define TEST_INIT_SECOND_RC 0xdead555
static void
tctildr_init_ex_null_test (void **state)
{
    TSS2_RC rc;

    rc = Tss2_TctiLdr_Initialize_Ex (NULL, NULL, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}
static void
tctildr_init_null_test (void **state)
{
    TSS2_RC rc;

    rc = Tss2_TctiLdr_Initialize (NULL, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}
#define NAME_CONF_STR (char*)0xf100d
size_t __real_strlen (const char *s);
size_t
__wrap_strlen (const char *s)
{
    if (s != NAME_CONF_STR)
        return __real_strlen (s);
    return mock_type (size_t);
}
static void
tctildr_init_conf_fail_test (void **state)
{
    TSS2_RC rc;

    will_return (__wrap_strlen, PATH_MAX);
    rc = Tss2_TctiLdr_Initialize (NAME_CONF_STR, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}
TSS2_RC
__wrap_tctildr_get_info (const char *name,
                         const TSS2_TCTI_INFO **info,
                         void **data)
{
    TSS2_RC rc = mock_type (TSS2_RC);
    if (rc == TSS2_RC_SUCCESS) {
        *info = mock_type (TSS2_TCTI_INFO*);
        *data = mock_type (void*);
    }
    return rc;
}
TSS2_RC
__wrap_tctildr_get_tcti (const char *name,
                  const char* conf,
                  TSS2_TCTI_CONTEXT **tcti,
                  void **data)
{
    TSS2_RC rc = mock_type (TSS2_RC);
    if (rc == TSS2_RC_SUCCESS) {
        *tcti= mock_type (TSS2_TCTI_CONTEXT*);
        *data = mock_type (void*);
    }
    return rc;
}
void __wrap_tctildr_finalize_data (void **data) {}

static void
tctildr_init_ex_default_fail (void **state)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *context;

    will_return (__wrap_tctildr_get_tcti, TSS2_TCTI_RC_BAD_REFERENCE);
    rc = Tss2_TctiLdr_Initialize_Ex (NULL, NULL, &context);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_REFERENCE);
}
static void
tctildr_init_ex_from_file_fail (void **state)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *context;

    will_return (__wrap_tctildr_get_tcti, TSS2_TCTI_RC_BAD_REFERENCE);
    rc = Tss2_TctiLdr_Initialize_Ex ("foo", NULL, &context);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_REFERENCE);
}

static void
tctildr_init_ex_calloc_fail_test (void **state)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *ctx;

    will_return (__wrap_tctildr_get_tcti, TSS2_RC_SUCCESS);
    will_return (__wrap_tctildr_get_tcti, &v2_ctx);
    will_return (__wrap_tctildr_get_tcti, TEST_TCTI_HANDLE);
    will_return (__wrap_calloc, NULL);

    rc = Tss2_TctiLdr_Initialize_Ex (NULL, NULL, &ctx);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
static void
tctildr_init_ex_success_test (void **state)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *ctx;

    will_return (__wrap_tctildr_get_tcti, TSS2_RC_SUCCESS);
    will_return (__wrap_tctildr_get_tcti, &v2_ctx);
    will_return (__wrap_tctildr_get_tcti, TEST_TCTI_HANDLE);
    will_return (__wrap_calloc, &tctildr_ctx);

    rc = Tss2_TctiLdr_Initialize_Ex (NULL, NULL, &ctx);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
static void
tctildr_finalize_null_ref_test (void **state)
{
    Tss2_TctiLdr_Finalize (NULL);
    assert_int_equal (1, 1);
}
static void
tctildr_finalize_null_ctx_test (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = NULL;
    Tss2_TctiLdr_Finalize (&ctx);
    assert_int_equal (1, 1);
}
static void
tctildr_finalize_test (void **state)
{
    TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT*)&tctildr_ctx;

    TSS2_TCTI_VERSION(&tctildr_ctx) = 3;
    tctildr_ctx.library_handle = TEST_TCTI_HANDLE;
    TSS2_TCTI_MAGIC(&tctildr_ctx) = TCTILDR_MAGIC;
    tctildr_ctx.tcti = (TSS2_TCTI_CONTEXT*)&v2_ctx;
    Tss2_TctiLdr_Finalize (&ctx);
    assert_null (ctx);
}
int
main (int argc, char* arvg[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tctildr_init_ex_null_test),
        cmocka_unit_test (tctildr_init_null_test),
        cmocka_unit_test (tctildr_init_conf_fail_test),
        cmocka_unit_test (tctildr_init_ex_default_fail),
        cmocka_unit_test (tctildr_init_ex_from_file_fail),
        cmocka_unit_test (tctildr_init_ex_calloc_fail_test),
        cmocka_unit_test (tctildr_init_ex_success_test),
        cmocka_unit_test (tctildr_finalize_null_ref_test),
        cmocka_unit_test (tctildr_finalize_null_ctx_test),
        cmocka_unit_test (tctildr_finalize_test),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
