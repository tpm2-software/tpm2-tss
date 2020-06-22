/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#include "tss2_fapi.h"

#define EXIT_SKIP 77
#define EXIT_ERROR 99

#define ASSERT_SIZE 10 /* sanity check value for string outputs of Fapi commands  */

#define goto_error_if_not_failed(rc,msg,label)                          \
    if (rc == TSS2_RC_SUCCESS) {                                        \
        LOG_ERROR("Error %s (%x) in Line %i: \n", msg, __LINE__, rc);   \
        goto label; }

/* This variable is set to the same value in order to allow usage in if-statements etc. */
extern char *fapi_profile;

#define FAPI_POLICIES TOP_SOURCEDIR "/test/data/fapi"

TSS2_RC
pcr_reset(FAPI_CONTEXT *context, UINT32 pcr);
/*
 * This is the prototype for all integration tests in the tpm2-tss
 * project. Integration tests are intended to exercise the combined
 * components in the software stack. This typically means executing some
 * SAPI function using the socket TCTI to communicate with a software
 * TPM2 simulator.
 * Return values:
 * A successful test will return 0, any other value indicates failure.
 */


int test_invoke_fapi(FAPI_CONTEXT * fapi_context);

int init_fapi(char *fapi_profile, FAPI_CONTEXT **fapi_context);
