/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef FAPI_POLICY_EXECUTE_H
#define FAPI_POLICY_EXECUTE_H

#include <stdbool.h>             // for bool
#include <stddef.h>              // for size_t
#include <stdint.h>              // for uint8_t

#include "fapi_int.h"            // for IFAPI_POLICY_EXEC_CTX
#include "fapi_types.h"          // for NODE_OBJECT_T
#include "ifapi_keystore.h"      // for IFAPI_OBJECT
#include "ifapi_policy_types.h"  // for TPMS_POLICY, TPMS_POLICYAUTHORIZATION
#include "tss2_common.h"         // for TSS2_RC
#include "tss2_esys.h"           // for ESYS_TR, ESYS_CONTEXT
#include "tss2_policy.h"         // for TSS2_POLICY_EXEC_CALLBACKS
#include "tss2_tpm2_types.h"     // for TPMI_ALG_HASH, TPM2B_DIGEST, TPM2B_NAME

TSS2_RC
ifapi_extend_authorization(
    TPMS_POLICY *policy,
    TPMS_POLICYAUTHORIZATION *authorization);

typedef TSS2_RC(*Policy_Compare_Object)(
    TPMS_POLICY *policy,
    void *object1,
    void *object2,
    bool *found);

/** List of policies which fulfill a certain predicate.
 *
 * The elements are stored in a linked list.
 */
struct POLICY_LIST {
    const char *path;            /**< The path of the policy object */
    TPMS_POLICY policy;          /**< The policy object */
    struct POLICY_LIST *next;    /**< Pointer to next element */
};

/** List of policies which fulfill a certain predicate.
 *
 * The elements are stored in a linked list.
 */
struct policy_object_node {
    const char *path;                  /**< The path of the policy object */
    TPMS_POLICY policy;                /**< The policy object */
    struct policy_object_node *next;   /**< Pointer to next element */
};

/** The states for policy execution */
enum IFAPI_STATE_POLICY_EXCECUTE {
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

typedef struct IFAPI_POLICY_CALLBACK_CTX IFAPI_POLICY_CALLBACK_CTX;

/** The context of the policy execution */
struct IFAPI_POLICY_EXEC_CTX {
    enum IFAPI_STATE_POLICY_EXCECUTE state;
                                    /**< The execution state of the current
                                         policy command */
    TPML_DIGEST digest_list;        /** The digest list of policy or */
    IFAPI_POLICY_EXEC_CTX *next;    /**< Pointer to next policy */
    IFAPI_POLICY_EXEC_CTX *prev;    /**< Pointer to previous policy */
    ESYS_TR session;                /**< The current policy session */
    TPMS_POLICY *policy;
    ESYS_TR policySessionSav;       /**< Backup policy session */
    ESYS_TR *enc_session;           /**< ession used for encryption if policy is used */

    ESYS_TR object_handle;
    ESYS_TR nv_index;
    ESYS_TR auth_handle;
    IFAPI_OBJECT auth_objectNV;       /**< Object used for NV authentication */
    IFAPI_OBJECT *auth_object;        /**< Object to be authorized */
    ESYS_TR auth_session;
    TPMI_ALG_HASH hash_alg;
    void  *app_data;                /**< Application data  for policy execution callbacks */
    NODE_OBJECT_T *policy_elements; /**< The policy elements to be executed */
    TPM2B_DIGEST *nonceTPM;
    uint8_t *buffer;
    size_t buffer_size;
    TPM2B_NAME name;
    char *pem_key;                   /**< Pem key recreated during policy execution */
    struct POLICY_LIST *policy_list;
                                    /**< List of policies for authorization selection */
    bool flush_handle;              /**< Handle to be flushed after policy execution */
    TSS2_POLICY_EXEC_CALLBACKS callbacks;
                                    /**< callbacks used for execution of sub
                                         policies and actions which require access
                                         to the FAPI context. */
};

TSS2_RC
ifapi_policyeval_execute_prepare(
    IFAPI_POLICY_EXEC_CTX *pol_ctx,
    TPMI_ALG_HASH hash_alg,
    TPMS_POLICY *policy);

TSS2_RC
ifapi_policyeval_execute(
    ESYS_CONTEXT *esys_ctx,
    IFAPI_POLICY_EXEC_CTX *current_policy,
    bool do_flush);

#endif /* FAPI_POLICY_EXECUTE_H */
