/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
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
