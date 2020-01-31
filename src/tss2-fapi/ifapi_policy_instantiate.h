/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifndef FAPI_POLICY_INSTANTIATE_H
#define FAPI_POLICY_INSTANTIATE_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include <json-c/json_util.h>

#include "tss2_esys.h"
#include "tss2_fapi.h"
//#include "fapi_int.h"
//#include "fapi_policy.h"
//#include "ifapi_keystore.h"

typedef TSS2_RC (*ifapi_policyeval_cbpublic) (
    const char *path,
    TPMT_PUBLIC *public,
    void *userdata);   /* e.g. for FAPI_CONTEXT */

typedef TSS2_RC (*ifapi_policyeval_cbname) (
    const char *path,
    TPM2B_NAME *name,
    void *userdata);   /* e.g. for FAPI_CONTEXT */

typedef TSS2_RC (*ifapi_policyeval_cbnvindex) (
    const char *path,
    TPMI_RH_NV_INDEX  *nv_index,
    void *userdata);   /* e.g. for FAPI_CONTEXT */

typedef TSS2_RC (*ifapi_policyeval_cbnvpublic) (
    const char *path,
    TPM2B_NV_PUBLIC *nv_public,
    void *userdata);   /* e.g. for FAPI_CONTEXT */

typedef TSS2_RC (*ifapi_policyeval_cbpemparam) (
    const char *keyPEM,
    TPMT_PUBLIC *keyPublic,
    TPM2B_NAME *name,
    void *userdata);   /* e.g. for FAPI_CONTEXT */

typedef TSS2_RC (*ifapi_policyeval_cbpcr) (
    TPMS_PCR_SELECT *pcrSelect,
    TPML_PCR_SELECTION *pcrBankSelect,
    TPML_PCRVALUES **pcrs,
    void *userdata);   /* e.g. for FAPI_CONTEXT */

typedef struct {
    ifapi_policyeval_cbpcr                cbpcr; /**< Callback to compute current PCR value */
    void                        *cbpcr_userdata;
    ifapi_policyeval_cbname              cbname; /**< Callback to compute name of an object from path */
    void                       *cbname_userdata;
    ifapi_policyeval_cbpublic          cbpublic; /**< Callback to compute public info of a key */
    void                     *cbpublic_userdata;
    ifapi_policyeval_cbnvpublic      cbnvpublic; /**< Callback to compute the NV public from path */
    void                   *cbnvpublic_userdata;
} ifapi_policyeval_INST_CB;

/** Type for representing the context for policy instantiation.
 */
typedef struct {
    TPMS_POLICY                         *policy; /**< The policy to be instantiated */
    NODE_OBJECT_T              *policy_elements; /** The policy elements to be instantiated */
    ifapi_policyeval_INST_CB          callbacks;
} IFAPI_POLICY_EVAL_INST_CTX;

TSS2_RC
ifapi_policyeval_instantiate_async(
    IFAPI_POLICY_EVAL_INST_CTX *context, /* For re-entry after try_again for offsets and such */
    TPMS_POLICY *policy,                 /* in */
    ifapi_policyeval_INST_CB *callbacks);
TSS2_RC

ifapi_policyeval_instantiate_finish(
    IFAPI_POLICY_EVAL_INST_CTX *context);

#endif /* FAPI_POLICY_INSTANTIATE_H */
