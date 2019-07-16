/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2019, Intel Corporation
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <limits.h>
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
TSS2_RC
__wrap_tctildr_get_tcti (const char *name,
                  const char* conf,
                  TSS2_TCTI_CONTEXT **tcti,
                  void **dlhandle)
{
    return TSS2_RC_SUCCESS;
}
void __wrap_tctildr_finalize_data (void **data){}

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
void
test_conf_parse_null (void **state)
{
    TSS2_RC rc = tctildr_conf_parse (NULL, NULL, NULL);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_REFERENCE);
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
char* __real_strchr (const char *s, int c);
char*
__wrap_strchr (const char *s, int c)
{
    if (s != NAME_CONF_STR)
        return __real_strchr (s, c);
    return mock_type (char*);
}
char* __real_strcpy(char *dest, const char *src);
char*
__wrap_strcpy(char *dest, const char *src)
{
    if (src != NAME_CONF_STR)
        return __real_strcpy (dest, src);
    return mock_type (char*);
}

void
test_conf_parse_bad_length (void **state)
{
    char name_buf[0], conf_buf[0];
    will_return (__wrap_strlen, PATH_MAX);
    TSS2_RC rc = tctildr_conf_parse (NAME_CONF_STR, name_buf, conf_buf);
    assert_int_equal (rc, TSS2_TCTI_RC_BAD_VALUE);
}
void
test_conf_parse_empty_str (void **state)
{
    char name_buf[0], conf_buf[0];
    TSS2_RC rc = tctildr_conf_parse ("", name_buf, conf_buf);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
void
test_conf_parse_no_colon (void **state)
{
    char name_buf[50] = { 0, }, conf_buf[50] = { 0, };
    TSS2_RC rc = tctildr_conf_parse ("foo", name_buf, conf_buf);
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
void
test_conf_parse_name_colon (void **state)
{
    char name_buf[50] = { 0, }, conf_buf[50] = { 0, };
    TSS2_RC rc = tctildr_conf_parse ("foo:", name_buf, conf_buf);
    assert_string_equal (name_buf, "foo");
    assert_int_equal (rc, TSS2_RC_SUCCESS);
}
void
test_conf_parse_name_colon_conf (void **state)
{
    char name_buf[50] = { 0, }, conf_buf[50] = { 0, };
    TSS2_RC rc = tctildr_conf_parse ("foo:bar", name_buf, conf_buf);
    assert_string_equal (name_buf, "foo");
    assert_string_equal (conf_buf, "bar");
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
        cmocka_unit_test(test_conf_parse_null),
        cmocka_unit_test(test_conf_parse_bad_length),
        cmocka_unit_test(test_conf_parse_empty_str),
        cmocka_unit_test(test_conf_parse_no_colon),
        cmocka_unit_test(test_conf_parse_name_colon),
        cmocka_unit_test(test_conf_parse_name_colon_conf),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
