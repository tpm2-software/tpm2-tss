/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IPOLICY_HELPERS_H
#define IPOLICY_HELPERS_H

// TODO change Makefile.am #include <json.h>    // for json_object
#include <stdbool.h> // for bool
#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t

#include "ifapi_policy_types.h" // for TPMT_PUBLIC
#include "tss2_common.h"        // for TSS2_RC

bool ipolicy_TPMT_PUBLIC_cmp(TPMT_PUBLIC *in1, TPMT_PUBLIC *in2);

#endif /* IPOLICY_HELPERS_H */
