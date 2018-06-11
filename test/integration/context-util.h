/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifndef CONTEXT_UTIL_H
#define CONTEXT_UTIL_H

#include "tss2_tcti.h"
#include "tss2_sys.h"

#include "test-options.h"

/**
 * functions to setup TCTIs and SAPI contexts  using data from the common
 * options
 */
TSS2_TCTI_CONTEXT *tcti_device_init(char const *device_name);
TSS2_TCTI_CONTEXT *tcti_socket_init(char const *address, uint16_t port);
TSS2_TCTI_CONTEXT *tcti_init_from_opts(test_opts_t * options);
TSS2_SYS_CONTEXT *sapi_init_from_opts(test_opts_t * options);
TSS2_SYS_CONTEXT *sapi_init_from_tcti_ctx(TSS2_TCTI_CONTEXT * tcti_ctx);
void tcti_teardown(TSS2_TCTI_CONTEXT * tcti_context);
void sapi_teardown(TSS2_SYS_CONTEXT * sapi_context);
void sapi_teardown_full(TSS2_SYS_CONTEXT * sapi_context);

#endif                          /* CONTEXT_UTIL_H */
