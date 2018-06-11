/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#include "tss2_esys.h"

#define TSSWG_INTEROP 1
#define TSS_SAPI_FIRST_FAMILY 2
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 108

#define goto_error_if_not_failed(rc,msg,label)                          \
    if (rc == TSS2_RC_SUCCESS) {                                        \
        LOG_ERROR("Error %s (%x) in Line %i: \n", msg, __LINE__, rc);   \
        goto label; }

/*
 * This is the prototype for all integration tests in the tpm2-tss
 * project. Integration tests are intended to exercise the combined
 * components in the software stack. This typically means executing some
 * SAPI function using the socket TCTI to communicate with a software
 * TPM2 simulator.
 * Return values:
 * A successful test will return 0, any other value indicates failure.
 */

int test_invoke_esapi(ESYS_CONTEXT * sapi_context);
