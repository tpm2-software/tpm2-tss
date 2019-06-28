/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2019, Intel Corporation
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_tcti.h"
#include "tss2-tcti/tctildr.h"

TSS2_TCTI_CONTEXT_COMMON_V2 tcti_ctx = { 0, };

TSS2_RC
local_init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *config)
{
    *size = mock_type (size_t);
    return mock_type (TSS2_RC);
}

void
tcti_from_init_null_init (void **state)
{
    TSS2_RC rc = tcti_from_init (NULL, NULL, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_REFERENCE);
}

#define TEST_MAGIC_SIZE (size_t)5513444
#define TEST_INIT_RC_FAIL (TSS2_RC)0x6134
void
tcti_from_init_init_fail (void **state)
{
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TEST_INIT_RC_FAIL);
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC rc = tcti_from_init (local_init, NULL, &tcti_ctx);
    assert_int_equal (rc, TEST_INIT_RC_FAIL);
}

void* __real_calloc (size_t nmemb, size_t size);
void*
__wrap_calloc (size_t nmemb, size_t size)
{
    if (size == TEST_MAGIC_SIZE)
        return mock_type (void*);
    else
        return __real_calloc (nmemb, size);
}
void __real_free (void *ptr);
void
__wrap_free (void *ptr)
{
    if (ptr != &tcti_ctx)
        __real_free (ptr);
    return;
}
void
tcti_from_init_calloc_fail (void **state)
{
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TSS2_RC_SUCCESS);
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    will_return(__wrap_calloc, NULL);
    TSS2_RC rc = tcti_from_init (local_init, NULL, &tcti_ctx);
    assert_int_equal (rc, TSS2_ESYS_RC_MEMORY);
}
void
tcti_from_init_second_init_fail (void **state)
{
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TSS2_RC_SUCCESS);
    TSS2_TCTI_CONTEXT *tcti_ctx_ptr = NULL;
    will_return(__wrap_calloc, &tcti_ctx);
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TEST_INIT_RC_FAIL);
    TSS2_RC rc = tcti_from_init (local_init, NULL, &tcti_ctx_ptr);
    assert_int_equal (rc, TEST_INIT_RC_FAIL);
}

void
tcti_from_init_success (void **state)
{
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TSS2_RC_SUCCESS);
    TSS2_TCTI_CONTEXT *tcti_ctx_ptr = NULL;
    will_return(__wrap_calloc, &tcti_ctx);
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TSS2_RC_SUCCESS);
    TSS2_RC rc = tcti_from_init (local_init, NULL, &tcti_ctx_ptr);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
TSS2_TCTI_INFO info = { .init = local_init, };
const TSS2_TCTI_INFO*
local_info (void)
{
    return mock_type (const TSS2_TCTI_INFO*);
}
void
tcti_from_info_info_null (void **state)
{
    TSS2_TCTI_CONTEXT *tcti_ctx_ptr = NULL;

    will_return (local_info, NULL);
    TSS2_RC rc = tcti_from_info (local_info, NULL, &tcti_ctx_ptr);
    assert_int_equal (rc, TSS2_ESYS_RC_GENERAL_FAILURE);
}
void
tcti_from_info_info_fail (void **state)
{
    TSS2_TCTI_CONTEXT *tcti_ctx_ptr = NULL;

    will_return (local_info, &info);
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TEST_INIT_RC_FAIL);
    TSS2_RC rc = tcti_from_info (local_info, NULL, &tcti_ctx_ptr);
    assert_int_equal (rc, TEST_INIT_RC_FAIL);
}
void
tcti_from_info_success (void **state)
{
    TSS2_TCTI_CONTEXT *tcti_ctx_ptr = NULL;

    will_return (local_info, &info);
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TSS2_RC_SUCCESS);
    will_return(__wrap_calloc, &tcti_ctx);
    will_return(local_init, TEST_MAGIC_SIZE);
    will_return(local_init, TSS2_RC_SUCCESS);
    TSS2_RC rc = tcti_from_info (local_info, NULL, &tcti_ctx_ptr);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(tcti_from_init_null_init),
        cmocka_unit_test(tcti_from_init_init_fail),
        cmocka_unit_test(tcti_from_init_calloc_fail),
        cmocka_unit_test(tcti_from_init_second_init_fail),
        cmocka_unit_test(tcti_from_init_success),
        cmocka_unit_test(tcti_from_info_info_null),
        cmocka_unit_test(tcti_from_info_info_fail),
        cmocka_unit_test(tcti_from_info_success),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
