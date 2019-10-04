/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TSS2_RC_H
#define TSS2_RC_H

#include <stdint.h>

#include "tss2_tpm2_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef const char *(*TSS2_RC_HANDLER)(TSS2_RC rc);

const char *Tss2_RC_Decode(TSS2_RC rc);

TSS2_RC_HANDLER Tss2_RC_SetHandler(uint8_t layer, const char *name, TSS2_RC_HANDLER handler);

#ifdef __cplusplus
}
#endif

#endif
