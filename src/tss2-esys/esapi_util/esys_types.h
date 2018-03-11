/*******************************************************************************
 * Copyright 2017, Fraunhofer SIT sponsored by Infineon Technologies AG
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
 *******************************************************************************/

#ifndef IESYS_TYPES_H
#define IESYS_TYPES_H

#define ESYS_MAX_SIZE_METADATA 3072

typedef UINT32 TSS2_ESYS_RC;

/**
 * @defgroup esys ESAPI (TSS Enhanced System API)
 */

#ifndef TSS2_RC_SUCCESS
#define TSS2_RC_SUCCESS 0
#endif

/**
 * @defgroup tss2_tpm_types Type Definitions
 * @ingroup tss2
 * @{
 */
/* Type of resource */
typedef UINT32 IESYSC_RESOURCE_TYPE_CONSTANT;
#define IESYSC_KEY_RSRC                1    /**< Tag for key resource */
#define IESYSC_NV_RSRC                 2    /**< Tag for NV Ram resource */
#define IESYSC_SESSION_RSRC            3    /**< Tag for session resources */
#define IESYSC_WITHOUT_MISC_RSRC       0    /**< Tag for other recources e.g. PCR register, hierarchies */

/* Type to indicate parameter encryption (by TPM) */
typedef UINT32 IESYSC_PARAM_ENCRYPT;
#define ENCRYPT                        1    /**< Parameter encryption by TPM */
#define NO_ENCRYPT                     0    /**< No parameter encryption by TPM */

/* Type to indicate parameter decryption (by TPM) */
typedef UINT32 IESYSC_PARAM_DECRYPT;
#define DECRYPT                        1    /**< Parameter decryption by TPM */
#define NO_DECRYPT                     0    /**< No parameter decryption by TPM */

/* Type of policy authorization */
typedef UINT32 IESYSC_TYPE_POLICY_AUTH;
#define POLICY_PASSWORD                2    /**< Marker to include auth value of the authorized object */
#define POLICY_AUTH                    1    /**< Marker to include the auth value in the HMAC key */
#define NO_POLICY_AUTH                 0    /**< no special handling */


/**
 * @defgroup tss2_tpm_types_IESYS_SESSION Typedef of IESYS_SESSION
   @ingroup  tss2_tpm_types
 * Type for representing TPM-Session
 * @{
 */
typedef struct {
    TPM2B_NAME                             bound_entity;    /**< Entity to which the session is bound */
    TPM2B_ENCRYPTED_SECRET                encryptedSalt;    /**< Encrypted salt which can be provided by application */
    TPM2B_DATA                                     salt;    /**< Salt computed if no encrypted salt is provided */
    TPMT_SYM_DEF                              symmetric;    /**< Algorithm selection for parameter encryption */
    TPMI_ALG_HASH                              authHash;    /**< Hashalg used for authorization */
    TPM2B_DIGEST                             sessionKey;    /**< sessionKey used for KDFa to compute symKey */
    TPM2_SE                                 sessionType;    /**< Type of the session (HMAC, Policy) */
    TPMA_SESSION                      sessionAttributes;    /**< Flags which define the session behaviour */
    TPM2B_NONCE                             nonceCaller;    /**< Nonce computed by the ESAPI for every session call */
    TPM2B_NONCE                                nonceTPM;    /**< Nonce which is returned by the TPM for every session call */
    IESYSC_PARAM_ENCRYPT                        encrypt;    /**< Indicate parameter encryption by the TPM */
    IESYSC_PARAM_ENCRYPT                        decrypt;    /**< Indicate parameter decryption by the TPM */
    IESYSC_TYPE_POLICY_AUTH         type_policy_session;    /**< Field to store markers for policy sessions */
    UINT16                             sizeSessionValue;    /**< Size of sessionKey plus optionally authValue */
    BYTE                 sessionValue [2*sizeof(TPMU_HA)];    /**< sessionKey || AuthValue */
} IESYS_SESSION;
/* @} */
/**
 * @defgroup tss2_tpm_types_IESYSC_RESOURCE_TYPE Typedef of IESYSC_RESOURCE_TYPE
   @ingroup  tss2_tpm_types
 * Selector type for esys resources
 * @{
 */
typedef UINT32                  IESYSC_RESOURCE_TYPE;
/* @} */
/**
 * @defgroup tss2_tpm_types_IESYS_RSRC_UNION Typedef of IESYS_RSRC_UNION
   @ingroup  tss2_tpm_types
 * Type for representing public info of a TPM-Resource
 * @{
 */
typedef union {
    TPM2B_PUBLIC                           rsrc_key_pub;    /**< Public info for key objects */
    TPM2B_NV_PUBLIC                         rsrc_nv_pub;    /**< Public info for NV ram objects */
    IESYS_SESSION                          rsrc_session;    /**< Internal esapi session information */
    TPMS_EMPTY                               rsrc_empty;    /**< no specialiced date for resource */
} IESYS_RSRC_UNION;
/* @} */
/**
 * @defgroup tss2_tpm_types_IESYS_RESOURCE Typedef of IESYS_RESOURCE
   @ingroup  tss2_tpm_types
 * Type for representing TPM-Resource
 * @{
 */
typedef struct {
    TPM2_HANDLE                                  handle;    /**< Handle used by TPM */
    TPM2B_NAME                                     name;    /**< TPM name of the object */
    BYTE                                   authValueSet;    /**< Indication whether auth value was set */
    IESYSC_RESOURCE_TYPE                       rsrcType;    /**< Selector for resource type */
    IESYS_RSRC_UNION                               misc;    /**< Resource specific information */
} IESYS_RESOURCE;
/* @} */
/**
 * @defgroup tss2_tpm_types_IESYS_METADATA Typedef of IESYS_METADATA
   @ingroup  tss2_tpm_types
 * Esys resource with size field
 * @{
 */
typedef struct {
    UINT16                                         size;    /**< size of the operand buffer */
    IESYS_RESOURCE                                 data;    /**< Esys resource data */

} IESYS_METADATA;
/* @} */
/**
 * @defgroup tss2_tpm_types_IESYS_CONTEXT_DATA Typedef of IESYS_CONTEXT_DATA
   @ingroup  tss2_tpm_types
 * Type for representing ESYS metadata
 * @{
 */
typedef struct {
    UINT32                                     reserved;    /**< Must allways be zero */
    TPM2B_CONTEXT_DATA                       tpmContext;    /**< Context information computed by tpm */
    IESYS_METADATA                         esysMetadata;    /**< Meta data of the ESY_TR object */
} IESYS_CONTEXT_DATA;
/* @} */
#endif /* IESYS_TYPES_H */
/* @} */
