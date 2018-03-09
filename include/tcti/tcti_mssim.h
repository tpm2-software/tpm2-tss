/*
 * Copyright (c) 2015 - 2018, Intel Corporation
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
 */
#ifndef TCTI_SOCKET_H
#define TCTI_SOCKET_H

#include <sapi/tss2_tcti.h>

/*
 * Command codes that may be sent to simulator through out of band command
 * channel (aka "the other socket").
 */
#define MS_SIM_POWER_ON         1
#define MS_SIM_POWER_OFF        2
#define MS_SIM_TPM_SEND_COMMAND 8
#define MS_SIM_CANCEL_ON        9
#define MS_SIM_CANCEL_OFF       10
#define MS_SIM_NV_ON            11
#define TPM_SESSION_END         20

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC tcti_platform_command(
    TSS2_TCTI_CONTEXT *tctiContext,
    UINT32 cmd);

TSS2_RC Tss2_Tcti_Mssim_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf);

#ifdef __cplusplus
}
#endif

#endif /* TCTI_SOCKET_H */
