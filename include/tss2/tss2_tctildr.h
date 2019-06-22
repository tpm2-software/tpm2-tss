/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2018-2019 Intel Corporation
 */
#ifndef TSS2_TCTILDR_H
#define TSS2_TCTILDR_H

#include <inttypes.h>
#include <stdlib.h>

#include "tss2_tpm2_types.h"
#include "tss2_tcti.h"

void
Tss2_TctiLdr_Finalize (TSS2_TCTI_CONTEXT **context);
TSS2_RC
Tss2_TctiLdr_Initialize_Ex (const char *name,
                            const char *conf,
                            TSS2_TCTI_CONTEXT **context);
TSS2_RC
Tss2_TctiLdr_Initialize (const char *nameConf,
                         TSS2_TCTI_CONTEXT **context);
TSS2_RC
Tss2_TctiLdr_GetInfo (const char *name,
                      TSS2_TCTI_INFO **info);
void
Tss2_TctiLdr_FreeInfo (TSS2_TCTI_INFO **info);

#endif /* TSS2_TCTILDR_H */
