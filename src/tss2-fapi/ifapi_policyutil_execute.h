/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef FAPI_POLICYUTIL_EXECUTE_H
#define FAPI_POLICYUTIL_EXECUTE_H

#include "fapi_int.h"            // for IFAPI_POLICYUTIL_STACK, IFAPI_POLICY...
#include "ifapi_policy_types.h"  // for TPMS_POLICY
#include "tss2_common.h"         // for TSS2_RC
#include "tss2_esys.h"           // for ESYS_TR
#include "tss2_fapi.h"           // for FAPI_CONTEXT
#include "tss2_tpm2_types.h"     // for TPMI_ALG_HASH


/** The states for the FAPI's policy util execution */
enum IFAPI_STATE_POLICY_UTIL_EXEC {
    POLICY_UTIL_INIT,
    POLICY_UTIL_EXEC_POLICY,
};

/** The context of the policy execution */
struct IFAPI_POLICYUTIL_STACK {
    ESYS_TR policy_session;             /**< The policy session created for the current evaluation  */
    IFAPI_POLICY_EXEC_CTX *pol_exec_ctx;    /**< The execution context for the current policy */
    enum IFAPI_STATE_POLICY_UTIL_EXEC state;
    IFAPI_POLICYUTIL_STACK *next;           /**< Pointer to next policy */
    IFAPI_POLICYUTIL_STACK *prev;           /**< Pointer to previous policy */
};

TSS2_RC
ifapi_policyutil_execute_prepare(
    FAPI_CONTEXT *context,
    TPMI_ALG_HASH hash_alg,
    TPMS_POLICY *policy);

TSS2_RC
ifapi_policyutil_execute(
    FAPI_CONTEXT *context,
    ESYS_TR *session);

#endif /* FAPI_POLICYUTIL_EXECUTE_H */
