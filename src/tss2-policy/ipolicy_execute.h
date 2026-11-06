/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef IPOLICY_EXECUTE_H
#define IPOLICY_EXECUTE_H

#include <stdbool.h> // for bool
#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t

#include "tss2_common.h"     // for TSS2_RC
#include "tss2_esys.h"       // for ESYS_TR, ESYS_CONTEXT
#include "tss2_policy.h"     // for TSS2_POLICY_EXEC_CALLBACKS
#include "tss2_tpm2_types.h" // for TPMI_ALG_HASH, TPM2B_DIGEST, TPM2B_NAME

/** The states for policy execution */
enum IPOLICY_STATE_EXCECUTE {
    POLICY_EXECUTE_INIT = 0,
    POLICY_EXECUTE_FINISH,
    POLICY_EXECUTE_CALLBACK,
    POLICY_LOAD_KEY,
    POLICY_LOAD_KEYEDHASH,
    POLICY_FLUSH_KEY,
    POLICY_VERIFY,
    POLICY_AUTH_CALLBACK,
    POLICY_AUTH_SENT,
    POLICY_EXEC_ESYS
};

/** The context of the policy execution */
struct IPOLICY_EXEC_CTX {
    enum IPOLICY_STATE_EXCECUTE state;
    /**< The execution state of the current
         policy command */
    TPML_DIGEST         digest_list; /** The digest list of policy or */
    ESYS_TR             session;     /**< The current policy session */
    struct TPMS_POLICY *policy;
    ESYS_TR            *enc_session; /**< ession used for encryption if policy is used */

    ESYS_TR                    object_handle;
    ESYS_TR                    nv_index;
    ESYS_TR                    auth_handle;
    TSS2_OBJECT               *auth_object; /**< Object to be authorized */
    ESYS_TR                    auth_session;
    TPMI_ALG_HASH              hash_alg;
    void                      *app_data; /**< Application data  for policy execution callbacks */
    NODE_OBJECT_T             *policy_elements; /**< The policy elements to be executed */
    TPM2B_DIGEST              *nonceTPM;
    uint8_t                   *buffer;
    size_t                     buffer_size;
    TPM2B_NAME                 name;
    char                      *pem_key;      /**< Pem key recreated during policy execution */
    bool                       flush_handle; /**< Handle to be flushed after policy execution */
    TSS2_POLICY_EXEC_CALLBACKS callbacks;
    /**< callbacks used for execution of sub
         policies and actions which require access
         to the FAPI context. */
};

TSS2_RC
ifapi_policyeval_execute_prepare(IPOLICY_EXEC_CTX   *pol_ctx,
                                 TPMI_ALG_HASH       hash_alg,
                                 struct TPMS_POLICY *policy);

TSS2_RC
ifapi_policyeval_execute(ESYS_CONTEXT *esys_ctx, IPOLICY_EXEC_CTX *current_policy, bool do_flush);

#endif /* IPOLICY_EXECUTE_H */
