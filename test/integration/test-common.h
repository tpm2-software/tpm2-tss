/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2017-2021, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include "tss2_esys.h"
#include "tss2_fapi.h"
#include "tss2_sys.h"
#include "tss2_tcti.h"

#define ENV_TCTI "TPM20TEST_TCTI"

#define TSSWG_INTEROP 1
#define TSS_SYS_FIRST_FAMILY 2
#define TSS_SYS_FIRST_LEVEL 1
#define TSS_SYS_FIRST_VERSION 108

#define TEST_ABI_VERSION { \
        .tssCreator = TSSWG_INTEROP, \
        .tssFamily = TSS_SYS_FIRST_FAMILY, \
        .tssLevel = TSS_SYS_FIRST_LEVEL, \
        .tssVersion = TSS_SYS_FIRST_VERSION, \
    }


//#define EXIT_SUCCESS 0
#define EXIT_ERROR 99

typedef struct tpm_state tpm_state;

typedef struct {
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_SYS_CONTEXT *sys_ctx;
    tpm_state *tpm_state;
} TSS2_TEST_SYS_CONTEXT;

int test_sys_setup(TSS2_TEST_SYS_CONTEXT **test_ctx);
int test_sys_checks_pre(TSS2_TEST_SYS_CONTEXT *test_ctx);
int test_sys_checks_post(TSS2_TEST_SYS_CONTEXT *test_ctx);
void test_sys_teardown(TSS2_TEST_SYS_CONTEXT *test_ctx);

typedef struct {
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_TCTI_CONTEXT *tcti_proxy_ctx;
    ESYS_CONTEXT *esys_ctx;
    tpm_state *tpm_state;
} TSS2_TEST_ESYS_CONTEXT;

int test_esys_setup(TSS2_TEST_ESYS_CONTEXT **test_ctx);
int test_esys_checks_pre(TSS2_TEST_ESYS_CONTEXT *test_ctx);
int test_esys_checks_post(TSS2_TEST_ESYS_CONTEXT *test_ctx);
void test_esys_teardown(TSS2_TEST_ESYS_CONTEXT *test_ctx);

typedef struct {
    FAPI_CONTEXT *fapi_ctx;
    char *tmpdir;
    char *fapi_profile;
    TSS2_TEST_ESYS_CONTEXT test_esys_ctx;
    tpm_state *tpm_state;
} TSS2_TEST_FAPI_CONTEXT;

int test_fapi_setup(TSS2_TEST_FAPI_CONTEXT **test_ctx);
int test_fapi_checks_pre(TSS2_TEST_FAPI_CONTEXT *test_ctx);
int test_fapi_checks_post(TSS2_TEST_FAPI_CONTEXT *test_ctx);
void test_fapi_teardown(TSS2_TEST_FAPI_CONTEXT *test_ctx);
void test_esys_teardown(TSS2_TEST_ESYS_CONTEXT *test_ctx);


#endif                          /* TEST_COMMON_H */
