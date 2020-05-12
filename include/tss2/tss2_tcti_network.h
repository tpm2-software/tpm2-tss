/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TSS2_TCTI_NETWORK_H
#define TSS2_TCTI_NETWORK_H

#include "tss2_tcti.h"

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC Tss2_Tcti_Network_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf);

TSS2_RC Tss2_Tcti_Network_Server_Init (
		TSS2_TCTI_CONTEXT *tctiContext,
	    size_t *size,
	    const char *conf);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_TCTI_NETWORK_H */
