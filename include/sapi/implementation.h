//**********************************************************************;
// Copyright (c) 2015 - 2017 Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

/* rev 119 */

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files. \
       Do not include this file, #include <sapi/tpm20.h> instead.
#endif  /* TSS2_API_VERSION_1_1_1_1 */

#ifndef _IMPLEMENTATION_H_
#define _IMPLEMENTATION_H_

#undef TRUE
#undef FALSE

// This table is built in to TpmStructures() Change these definitions to turn all algorithms or commands on or off
#define      ALG_YES      YES
#define      ALG_NO       NO
#define      CC_YES       YES
#define      CC_NO        NO

// From TPM 2.0 Part 2: Table 4 - Defines for Logic Values

#define  TRUE     1
#define  FALSE    0
#define  YES      1
#define  NO       0
#define  SET      1
#define  CLEAR    0

// From Vendor-Specific: Table 1 - Defines for Processor Values

#define BIG_ENDIAN_TPM       	NO	/*  to YES or NO according to the processor */
#define LITTLE_ENDIAN_TPM	YES	/*  to YES or NO according to the processor */
#define NO_AUTO_ALIGN		NO	/*  to YES if the processor does not allow unaligned accesses */

// From Vendor-Specific: Table 2 - Defines for Implemented Algorithms

#define  ALG_RSA               ALG_YES
#define  ALG_SHA1              ALG_YES
#define  ALG_HMAC              ALG_YES
#define  ALG_AES               ALG_YES
#define  ALG_MGF1              ALG_YES
#define  ALG_XOR               ALG_YES
#define  ALG_KEYEDHASH         ALG_YES
#define  ALG_SHA256            ALG_YES
#define  ALG_SHA384            ALG_YES
#define  ALG_SHA512            ALG_YES
#define  ALG_SM3_256           ALG_YES
#define  ALG_SM4               ALG_YES
#define  ALG_RSASSA            (ALG_YES*ALG_RSA)
#define  ALG_RSAES             (ALG_YES*ALG_RSA)
#define  ALG_RSAPSS            (ALG_YES*ALG_RSA)
#define  ALG_OAEP              (ALG_YES*ALG_RSA)
#define  ALG_ECC               ALG_YES
#define  ALG_ECDH              (ALG_YES*ALG_ECC)
#define  ALG_ECDSA             (ALG_YES*ALG_ECC)
#define  ALG_ECDAA             (ALG_YES*ALG_ECC)
#define  ALG_SM2               (ALG_YES*ALG_ECC)
#define  ALG_ECSCHNORR         (ALG_YES*ALG_ECC)
#define  ALG_ECMQV             (ALG_NO*ALG_ECC)
#define  ALG_SYMCIPHER         ALG_YES
#define  ALG_KDF1_SP800_56A    (ALG_YES*ALG_ECC)
#define  ALG_KDF2              ALG_NO
#define  ALG_KDF1_SP800_108    ALG_YES
#define  ALG_CTR               ALG_YES
#define  ALG_OFB               ALG_YES
#define  ALG_CBC               ALG_YES
#define  ALG_CFB               ALG_YES
#define  ALG_ECB               ALG_YES

// From Vendor-Specific: Table 4 - Defines for Key Size Constants

#define  RSA_KEY_SIZES_BITS         {1024,2048}
#define  RSA_KEY_SIZE_BITS_1024     RSA_ALLOWED_KEY_SIZE_1024
#define  RSA_KEY_SIZE_BITS_2048     RSA_ALLOWED_KEY_SIZE_2048
#define  MAX_RSA_KEY_BITS           2048
#define  MAX_RSA_KEY_BYTES          256
#define  AES_KEY_SIZES_BITS         {128,256}
#define  AES_KEY_SIZE_BITS_128      AES_ALLOWED_KEY_SIZE_128
#define  AES_KEY_SIZE_BITS_256      AES_ALLOWED_KEY_SIZE_256
#define  MAX_AES_KEY_BITS           256
#define  MAX_AES_KEY_BYTES          32
#define MAX_AES_BLOCK_SIZE_BYTES				      \
    MAX(AES_128_BLOCK_SIZE_BYTES,					\
	MAX(AES_256_BLOCK_SIZE_BYTES, 0))
#define  SM4_KEY_SIZES_BITS         {128}
#define  SM4_KEY_SIZE_BITS_128      SM4_ALLOWED_KEY_SIZE_128
#define  MAX_SM4_KEY_BITS           128
#define  MAX_SM4_KEY_BYTES          16
#define MAX_SM4_BLOCK_SIZE_BYTES			\
    MAX(SM4_128_BLOCK_SIZE_BYTES, 0)
#define  CAMELLIA_KEY_SIZES_BITS    {128}
#define  CAMELLIA_KEY_SIZE_BITS_128    CAMELLIA_ALLOWED_KEY_SIZE_128
#define  MAX_CAMELLIA_KEY_BITS      128
#define  MAX_CAMELLIA_KEY_BYTES     16
#define MAX_CAMELLIA_BLOCK_SIZE_BYTES				\
    MAX(CAMELLIA_128_BLOCK_SIZE_BYTES, 0)

// From Vendor-Specific: Table 5 - Defines for Implemented Curves

#define  ECC_NIST_P256         YES
#define  ECC_NIST_P384         YES
#define  ECC_BN_P256           YES
#define  ECC_CURVES							\
    {TPM_ECC_BN_P256, TPM_ECC_NIST_P256, TPM_ECC_NIST_P384}
#define  ECC_KEY_SIZES_BITS    {256, 384}
#define  ECC_KEY_SIZE_BITS_256
#define  ECC_KEY_SIZE_BITS_384
#define  MAX_ECC_KEY_BITS      384
#define  MAX_ECC_KEY_BYTES     48

// From Vendor-Specific: Table 6 - Defines for Implemented Commands

#define  CC_ActivateCredential            CC_YES
#define  CC_Certify                       CC_YES
#define  CC_CertifyCreation               CC_YES
#define  CC_ChangeEPS                     CC_YES
#define  CC_ChangePPS                     CC_YES
#define  CC_Clear                         CC_YES
#define  CC_ClearControl                  CC_YES
#define  CC_ClockRateAdjust               CC_YES
#define  CC_ClockSet                      CC_YES
#define  CC_Commit                        (CC_YES*ALG_ECC)
#define  CC_ContextLoad                   CC_YES
#define  CC_ContextSave                   CC_YES
#define  CC_Create                        CC_YES
#define  CC_CreatePrimary                 CC_YES
#define  CC_DictionaryAttackLockReset     CC_YES
#define  CC_DictionaryAttackParameters    CC_YES
#define  CC_Duplicate                     CC_YES
#define  CC_ECC_Parameters                (CC_YES*ALG_ECC)
#define  CC_ECDH_KeyGen                   (CC_YES*ALG_ECC)
#define  CC_ECDH_ZGen                     (CC_YES*ALG_ECC)
#define  CC_EncryptDecrypt                CC_YES
#define  CC_EventSequenceComplete         CC_YES
#define  CC_EvictControl                  CC_YES
#define  CC_FieldUpgradeData              CC_YES
#define  CC_FieldUpgradeStart             CC_YES
#define  CC_FirmwareRead                  CC_YES
#define  CC_FlushContext                  CC_YES
#define  CC_GetCapability                 CC_YES
#define  CC_GetCommandAuditDigest         CC_YES
#define  CC_GetRandom                     CC_YES
#define  CC_GetSessionAuditDigest         CC_YES
#define  CC_GetTestResult                 CC_YES
#define  CC_GetTime                       CC_YES
#define  CC_Hash                          CC_YES
#define  CC_HashSequenceStart             CC_YES
#define  CC_HierarchyChangeAuth           CC_YES
#define  CC_HierarchyControl              CC_YES
#define  CC_HMAC                          CC_YES
#define  CC_HMAC_Start                    CC_YES
#define  CC_Import                        CC_YES
#define  CC_IncrementalSelfTest           CC_YES
#define  CC_Load                          CC_YES
#define  CC_LoadExternal                  CC_YES
#define  CC_MakeCredential                CC_YES
#define  CC_NV_Certify                    CC_YES
#define  CC_NV_ChangeAuth                 CC_YES
#define  CC_NV_DefineSpace                CC_YES
#define  CC_NV_Extend                     CC_YES
#define  CC_NV_GlobalWriteLock            CC_YES
#define  CC_NV_Increment                  CC_YES
#define  CC_NV_Read                       CC_YES
#define  CC_NV_ReadLock                   CC_YES
#define  CC_NV_ReadPublic                 CC_YES
#define  CC_NV_SetBits                    CC_YES
#define  CC_NV_UndefineSpace              CC_YES
#define  CC_NV_UndefineSpaceSpecial       CC_YES
#define  CC_NV_Write                      CC_YES
#define  CC_NV_WriteLock                  CC_YES
#define  CC_ObjectChangeAuth              CC_YES
#define  CC_PCR_Allocate                  CC_YES
#define  CC_PCR_Event                     CC_YES
#define  CC_PCR_Extend                    CC_YES
#define  CC_PCR_Read                      CC_YES
#define  CC_PCR_Reset                     CC_YES
#define  CC_PCR_SetAuthPolicy             CC_YES
#define  CC_PCR_SetAuthValue              CC_YES
#define  CC_PolicyAuthorize               CC_YES
#define  CC_PolicyAuthValue               CC_YES
#define  CC_PolicyCommandCode             CC_YES
#define  CC_PolicyCounterTimer            CC_YES
#define  CC_PolicyCpHash                  CC_YES
#define  CC_PolicyDuplicationSelect       CC_YES
#define  CC_PolicyGetDigest               CC_YES
#define  CC_PolicyLocality                CC_YES
#define  CC_PolicyNameHash                CC_YES
#define  CC_PolicyNV                      CC_YES
#define  CC_PolicyOR                      CC_YES
#define  CC_PolicyPassword                CC_YES
#define  CC_PolicyPCR                     CC_YES
#define  CC_PolicyPhysicalPresence        CC_YES
#define  CC_PolicyRestart                 CC_YES
#define  CC_PolicySecret                  CC_YES
#define  CC_PolicySigned                  CC_YES
#define  CC_PolicyTicket                  CC_YES
#define  CC_PP_Commands                   CC_YES
#define  CC_Quote                         CC_YES
#define  CC_ReadClock                     CC_YES
#define  CC_ReadPublic                    CC_YES
#define  CC_Rewrap                        CC_YES
#define  CC_RSA_Decrypt                   (CC_YES*ALG_RSA)
#define  CC_RSA_Encrypt                   (CC_YES*ALG_RSA)
#define  CC_SelfTest                      CC_YES
#define  CC_SequenceComplete              CC_YES
#define  CC_SequenceUpdate                CC_YES
#define  CC_SetAlgorithmSet               CC_YES
#define  CC_SetCommandCodeAuditStatus     CC_YES
#define  CC_SetPrimaryPolicy              CC_YES
#define  CC_Shutdown                      CC_YES
#define  CC_Sign                          CC_YES
#define  CC_StartAuthSession              CC_YES
#define  CC_Startup                       CC_YES
#define  CC_StirRandom                    CC_YES
#define  CC_TestParms                     CC_YES
#define  CC_Unseal                        CC_YES
#define  CC_VerifySignature               CC_YES
#define  CC_ZGen_2Phase                   (CC_YES*ALG_ECC)
#define  CC_EC_Ephemeral                  (CC_YES*ALG_ECC)
#define  CC_PolicyNvWritten               CC_YES
#define  CC_EncryptDecrypt2               CC_YES
#define  CC_Vendor_TCG_Test               CC_YES
#define  CC_AC_GetCapability              CC_YES
#define  CC_AC_Send                       CC_YES
#define  CC_Policy_AC_SendSelect          CC_YES

// From Vendor-Specific: Table 7 - Defines for Implementation Values

#define FIELD_UPGRADE_IMPLEMENTED	NO	/* temporary define */
#define BSIZE				UINT16	/* size used for internal storage of the size field of a TPM2B */
#define BUFFER_ALIGNMENT		4	/* sets the size granularity for the buffers in a TPM2B structure */
#define IMPLEMENTATION_PCR		24	/* the number of PCR in the TPM */
#define PLATFORM_PCR			24	/* the number of PCR required by the relevant platform specification */
#define DRTM_PCR			17	/* the DRTM PCR */
#define HCRTM_PCR			0	/* PCR that will receive the H-CRTM value at
						   TPM2_Startup.  This value should not be changed. */
#define NUM_LOCALITIES			5	/* the number of localities supported by the TPM */
#define MAX_HANDLE_NUM			3	/* the maximum number of handles in the handle area */
#define MAX_ACTIVE_SESSIONS		64	/* the number of simultaneously active sessions that
						   are supported by the TPM implementation */
#define CONTEXT_SLOT                     UINT16	/* the type of an entry in the array of
						   saved contexts */
#define CONTEXT_COUNTER                  UINT64	/* the type of the saved session counter */
#define MAX_LOADED_SESSIONS		3	/* the number of sessions that the TPM may have in memory */
#define MAX_SESSION_NUM 		3	/* this is the current maximum value */
#define MAX_LOADED_OBJECTS		3	/* the number of simultaneously loaded objects that
						   are supported by the TPM */
#define MIN_EVICT_OBJECTS		2	/* the minimum number of evict objects supported by the TPM */
#define PCR_SELECT_MIN			((PLATFORM_PCR+7)/8)
#define PCR_SELECT_MAX			((IMPLEMENTATION_PCR+7)/8)
#define NUM_POLICY_PCR_GROUP 		1	/* number of PCR groups that have individual policies */
#define NUM_AUTHVALUE_PCR_GROUP		1	/* number of PCR groups that have individual authorization values */
#define MAX_CONTEXT_SIZE		2048	/* This may be larger than necessary */
#define MAX_DIGEST_BUFFER		1024
#define MAX_NV_INDEX_SIZE               2048		/* maximum data size allowed in an NV Index */
#define MAX_NV_BUFFER_SIZE              1024
#define MAX_CAP_BUFFER                  1024
#define NV_MEMORY_SIZE                  16384	/* size of NV memory in octets */
#define NUM_STATIC_PCR                  16
#define MAX_ALG_LIST_SIZE               64	/* number of algorithms that can be in a list */
#define TIMER_PRESCALE                  100000	/* nominal value for the pre-scale value of Clock */
#define PRIMARY_SEED_SIZE               32	/* size of the Primary Seed in octets */
#define CONTEXT_ENCRYPT_ALG		TPM_ALG_AES			/* context encryption algorithm */
#define CONTEXT_ENCRYPT_KEY_BITS	MAX_SYM_KEY_BITS		/* context encryption key size in bits */
#define CONTEXT_ENCRYPT_KEY_BYTES	((CONTEXT_ENCRYPT_KEY_BITS+7)/8)
#define CONTEXT_INTEGRITY_HASH_ALG	TPM_ALG_SHA256			/* context integrity hash
									   algorithm */
#define CONTEXT_INTEGRITY_HASH_SIZE	SHA256_DIGEST_SIZE		/* number of byes in the
									   context integrity
									   digest */
#define PROOF_SIZE			CONTEXT_INTEGRITY_HASH_SIZE	/* size of proof value in octets */
#define NV_CLOCK_UPDATE_INTERVAL	12	/* the update interval expressed as a power of 2 seconds */
#define NUM_POLICY_PCR			1	/* number of PCR that allow policy/auth */
#define MAX_COMMAND_SIZE		4096	/* maximum size of a command */
#define MAX_RESPONSE_SIZE		4096	/* maximum size of a response */
#define ORDERLY_BITS			8	/* number between 1 and 32 inclusive */
#define MAX_ORDERLY_COUNT               ((1<<ORDERLY_BITS)-1)	/* maximum count of orderly counter
								   before NV is updated.  This must
								   be of the form 2N - 1 where 1 = N
								   = 32. */
#define ALG_ID_FIRST			TPM_ALG_FIRST	/* used by GetCapability() processing to
							   bound the algorithm search */
#define ALG_ID_LAST			TPM_ALG_LAST	/* used by GetCapability() processing to
							   bound the algorithm search */
#define MAX_SYM_DATA			128		/* this is the maximum number of octets that
							   may be in a sealed blob. */
#define MAX_RNG_ENTROPY_SIZE		64
#define RAM_INDEX_SPACE			512
#define RSA_DEFAULT_PUBLIC_EXPONENT	0x00010001	/* 2^^16 + 1 */
#define ENABLE_PCR_NO_INCREMENT		YES		/* indicates if the TPM_PT_PCR_NO_INCREMENT
							   group is implemented */
#define CRT_FORMAT_RSA			YES
#define  VENDOR_COMMAND_COUNT             0
#define  PRIVATE_VENDOR_SPECIFIC_BYTES				\
    ((MAX_RSA_KEY_BYTES/2)*(3+CRT_FORMAT_RSA*2))
#define  MAX_VENDOR_BUFFER_SIZE           1024

// From TCG Algorithm Registry: Table 2 - Definition of TPM_ALG_ID Constants

typedef  UINT16             TPM_ALG_ID;
#define  TPM_ALG_ERROR               0x0000
#define  ALG_ERROR_VALUE             0x0000
#if defined ALG_RSA && ALG_RSA == YES
#define  TPM_ALG_RSA                 0x0001
#endif
#define  ALG_RSA_VALUE               0x0001
#if defined ALG_SHA && ALG_SHA == YES
#define  TPM_ALG_SHA                 0x0004
#endif
#define  ALG_SHA_VALUE               0x0004
#if defined ALG_SHA1 && ALG_SHA1 == YES
#define  TPM_ALG_SHA1                0x0004
#endif
#define  ALG_SHA1_VALUE              0x0004
#if defined ALG_HMAC && ALG_HMAC == YES
#define  TPM_ALG_HMAC                0x0005
#endif
#define  ALG_HMAC_VALUE              0x0005
#if defined ALG_AES && ALG_AES == YES
#define  TPM_ALG_AES                 0x0006
#endif
#define  ALG_AES_VALUE               0x0006
#if defined ALG_MGF1 && ALG_MGF1 == YES
#define  TPM_ALG_MGF1                0x0007
#endif
#define  ALG_MGF1_VALUE              0x0007
#if defined ALG_KEYEDHASH && ALG_KEYEDHASH == YES
#define  TPM_ALG_KEYEDHASH           0x0008
#endif
#define  ALG_KEYEDHASH_VALUE         0x0008
#if defined ALG_XOR && ALG_XOR == YES
#define  TPM_ALG_XOR                 0x000A
#endif
#define  ALG_XOR_VALUE               0x000A
#if defined ALG_SHA256 && ALG_SHA256 == YES
#define  TPM_ALG_SHA256              0x000B
#endif
#define  ALG_SHA256_VALUE            0x000B
#if defined ALG_SHA384 && ALG_SHA384 == YES
#define  TPM_ALG_SHA384              0x000C
#endif
#define  ALG_SHA384_VALUE            0x000C
#if defined ALG_SHA512 && ALG_SHA512 == YES
#define  TPM_ALG_SHA512              0x000D
#endif
#define  ALG_SHA512_VALUE            0x000D
#define  TPM_ALG_NULL                0x0010
#define  ALG_NULL_VALUE              0x0010
#if defined ALG_SM3_256 && ALG_SM3_256 == YES
#define  TPM_ALG_SM3_256             0x0012
#endif
#define  ALG_SM3_256_VALUE           0x0012
#if defined ALG_SM4 && ALG_SM4 == YES
#define  TPM_ALG_SM4                 0x0013
#endif
#define  ALG_SM4_VALUE               0x0013
#if defined ALG_RSASSA && ALG_RSASSA == YES
#define  TPM_ALG_RSASSA              0x0014
#endif
#define  ALG_RSASSA_VALUE            0x0014
#if defined ALG_RSAES && ALG_RSAES == YES
#define  TPM_ALG_RSAES               0x0015
#endif
#define  ALG_RSAES_VALUE             0x0015
#if defined ALG_RSAPSS && ALG_RSAPSS == YES
#define  TPM_ALG_RSAPSS              0x0016
#endif
#define  ALG_RSAPSS_VALUE            0x0016
#if defined ALG_OAEP && ALG_OAEP == YES
#define  TPM_ALG_OAEP                0x0017
#endif
#define  ALG_OAEP_VALUE              0x0017
#if defined ALG_ECDSA && ALG_ECDSA == YES
#define  TPM_ALG_ECDSA               0x0018
#endif
#define  ALG_ECDSA_VALUE             0x0018
#if defined ALG_ECDH && ALG_ECDH == YES
#define  TPM_ALG_ECDH                0x0019
#endif
#define  ALG_ECDH_VALUE              0x0019
#if defined ALG_ECDAA && ALG_ECDAA == YES
#define  TPM_ALG_ECDAA               0x001A
#endif
#define  ALG_ECDAA_VALUE             0x001A
#if defined ALG_SM2 && ALG_SM2 == YES
#define  TPM_ALG_SM2                 0x001B
#endif
#define  ALG_SM2_VALUE               0x001B
#if defined ALG_ECSCHNORR && ALG_ECSCHNORR == YES
#define  TPM_ALG_ECSCHNORR           0x001C
#endif
#define  ALG_ECSCHNORR_VALUE         0x001C
#if defined ALG_ECMQV && ALG_ECMQV == YES
#define  TPM_ALG_ECMQV               0x001D
#endif
#define  ALG_ECMQV_VALUE             0x001D
#if defined ALG_KDF1_SP800_56A && ALG_KDF1_SP800_56A == YES
#define  TPM_ALG_KDF1_SP800_56A      0x0020
#endif
#define  ALG_KDF1_SP800_56A_VALUE    0x0020
#if defined ALG_KDF2 && ALG_KDF2 == YES
#define  TPM_ALG_KDF2                0x0021
#endif
#define  ALG_KDF2_VALUE              0x0021
#if defined ALG_KDF1_SP800_108 && ALG_KDF1_SP800_108 == YES
#define  TPM_ALG_KDF1_SP800_108      0x0022
#endif
#define  ALG_KDF1_SP800_108_VALUE    0x0022
#if defined ALG_ECC && ALG_ECC == YES
#define  TPM_ALG_ECC                 0x0023
#endif
#define  ALG_ECC_VALUE               0x0023
#if defined ALG_SYMCIPHER && ALG_SYMCIPHER == YES
#define  TPM_ALG_SYMCIPHER           0x0025
#endif
#define  ALG_SYMCIPHER_VALUE         0x0025
#if defined ALG_CAMELLIA && ALG_CAMELLIA == YES
#define  TPM_ALG_CAMELLIA            0x0026
#endif
#define  ALG_CAMELLIA_VALUE          0x0026
#if defined ALG_CTR && ALG_CTR == YES
#define  TPM_ALG_CTR                 0x0040
#endif
#define  ALG_CTR_VALUE               0x0040
#if defined ALG_OFB && ALG_OFB == YES
#define  TPM_ALG_OFB                 0x0041
#endif
#define  ALG_OFB_VALUE               0x0041
#if defined ALG_CBC && ALG_CBC == YES
#define  TPM_ALG_CBC                 0x0042
#endif
#define  ALG_CBC_VALUE               0x0042
#if defined ALG_CFB && ALG_CFB == YES
#define  TPM_ALG_CFB                 0x0043
#endif
#define  ALG_CFB_VALUE               0x0043
#if defined ALG_ECB && ALG_ECB == YES
#define  TPM_ALG_ECB                 0x0044
#endif
#define  ALG_ECB_VALUE               0x0044
#define  TPM_ALG_FIRST               0x0001
#define  ALG_FIRST_VALUE             0x0001
#define  TPM_ALG_LAST                0x0044
#define  ALG_LAST_VALUE              0x0044
//     From TCG Algorithm Registry: Table 3 - Definition of TPM_ECC_CURVE Constants

typedef  UINT16             TPM_ECC_CURVE;
#define  TPM_ECC_NONE         (TPM_ECC_CURVE)(0x0000)
#define  TPM_ECC_NIST_P192    (TPM_ECC_CURVE)(0x0001)
#define  TPM_ECC_NIST_P224    (TPM_ECC_CURVE)(0x0002)
#define  TPM_ECC_NIST_P256    (TPM_ECC_CURVE)(0x0003)
#define  TPM_ECC_NIST_P384    (TPM_ECC_CURVE)(0x0004)
#define  TPM_ECC_NIST_P521    (TPM_ECC_CURVE)(0x0005)
#define  TPM_ECC_BN_P256      (TPM_ECC_CURVE)(0x0010)
#define  TPM_ECC_BN_P638      (TPM_ECC_CURVE)(0x0011)
#define  TPM_ECC_SM2_P256     (TPM_ECC_CURVE)(0x0020)

// From TCG Algorithm Registry: Table 4 - Defines for NIST_P192 ECC Values Data in CrpiEccData.c
// From TCG Algorithm Registry: Table 5 - Defines for NIST_P224 ECC Values Data in CrpiEccData.c
// From TCG Algorithm Registry: Table 6 - Defines for NIST_P256 ECC Values Data in CrpiEccData.c
// From TCG Algorithm Registry: Table 7 - Defines for NIST_P384 ECC Values Data in CrpiEccData.c
// From TCG Algorithm Registry: Table 8 - Defines for NIST_P521 ECC Values Data in CrpiEccData.c
// From TCG Algorithm Registry: Table 9 - Defines for BN_P256 ECC Values Data in CrpiEccData.c
// From TCG Algorithm Registry: Table 10 - Defines for BN_P638 ECC Values Data in CrpiEccData.c
// From TCG Algorithm Registry: Table 11 - Defines for SM2_P256 ECC Values Data in CrpiEccData.c

// From TCG Algorithm Registry: Table 12 - Defines for SHA1 Hash Values
#define  SHA1_DIGEST_SIZE    20
#define  SHA1_BLOCK_SIZE     64
#define  SHA1_DER_SIZE       15
#define  SHA1_DER							\
    0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14

// From TCG Algorithm Registry: Table 13 - Defines for SHA256 Hash Values
#define  SHA256_DIGEST_SIZE    32
#define  SHA256_BLOCK_SIZE     64
#define  SHA256_DER_SIZE       19
#define  SHA256_DER							\
    0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20

// From TCG Algorithm Registry: Table 14 - Defines for SHA384 Hash Values
#define  SHA384_DIGEST_SIZE    48
#define  SHA384_BLOCK_SIZE     128
#define  SHA384_DER_SIZE       19
#define  SHA384_DER							\
    0x30,0x41,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30

// From TCG Algorithm Registry: Table 15 - Defines for SHA512 Hash Values
#define  SHA512_DIGEST_SIZE    64
#define  SHA512_BLOCK_SIZE     128
#define  SHA512_DER_SIZE       19
#define  SHA512_DER							\
    0x30,0x51,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40

// From TCG Algorithm Registry: Table 16 - Defines for SM3_256 Hash Values
#define  SM3_256_DIGEST_SIZE    32
#define  SM3_256_BLOCK_SIZE     64
#define  SM3_256_DER_SIZE       18
#define  SM3_256_DER							\
    0x30,0x30,0x30,0x0C,0x06,0x08,0x2A,0x81,0x1C,0x81,0x45,0x01,0x83,0x11,0x05,0x00,0x04,0x20

// From TCG Algorithm Registry: Table 17 - Defines for AES Symmetric Cipher Algorithm Constants
#define  AES_ALLOWED_KEY_SIZE_128    YES
#define  AES_ALLOWED_KEY_SIZE_192    YES
#define  AES_ALLOWED_KEY_SIZE_256    YES
#define  AES_128_BLOCK_SIZE_BYTES    16
#define  AES_192_BLOCK_SIZE_BYTES    16
#define  AES_256_BLOCK_SIZE_BYTES    16

// From TCG Algorithm Registry: Table 18 - Defines for SM4 Symmetric Cipher Algorithm Constants
#define  SM4_ALLOWED_KEY_SIZE_128    YES
#define  SM4_128_BLOCK_SIZE_BYTES    16

// From TCG Algorithm Registry: Table 19 - Defines for CAMELLIA Symmetric Cipher Algorithm Constants
#define  CAMELLIA_ALLOWED_KEY_SIZE_128    YES
#define  CAMELLIA_ALLOWED_KEY_SIZE_192    YES
#define  CAMELLIA_ALLOWED_KEY_SIZE_256    YES
#define  CAMELLIA_128_BLOCK_SIZE_BYTES    16
#define  CAMELLIA_192_BLOCK_SIZE_BYTES    16
#define  CAMELLIA_256_BLOCK_SIZE_BYTES    16

// From TPM 2.0 Part 2: Table 13 - Definition of TPM_CC Constants

typedef  UINT32             TPM_CC;

#ifndef CC_NV_UndefineSpaceSpecial
#   define CC_NV_UndefineSpaceSpecial NO
#endif
#if CC_NV_UndefineSpaceSpecial == YES
#define  TPM_CC_NV_UndefineSpaceSpecial       (TPM_CC)(0x0000011f)
#endif

#define TPM_CC_FIRST TPM_CC_NV_UndefineSpaceSpecial

#ifndef CC_EvictControl
#   define CC_EvictControl NO
#endif
#if CC_EvictControl == YES
#define  TPM_CC_EvictControl                  (TPM_CC)(0x00000120)
#endif
#ifndef CC_HierarchyControl
#   define CC_HierarchyControl NO
#endif
#if CC_HierarchyControl == YES
#define  TPM_CC_HierarchyControl              (TPM_CC)(0x00000121)
#endif
#ifndef CC_NV_UndefineSpace
#   define CC_NV_UndefineSpace NO
#endif
#if CC_NV_UndefineSpace == YES
#define  TPM_CC_NV_UndefineSpace              (TPM_CC)(0x00000122)
#endif
#ifndef CC_ChangeEPS
#   define CC_ChangeEPS NO
#endif
#if CC_ChangeEPS == YES
#define  TPM_CC_ChangeEPS                     (TPM_CC)(0x00000124)
#endif
#ifndef CC_ChangePPS
#   define CC_ChangePPS NO
#endif
#if CC_ChangePPS == YES
#define  TPM_CC_ChangePPS                     (TPM_CC)(0x00000125)
#endif
#ifndef CC_Clear
#   define CC_Clear NO
#endif
#if CC_Clear == YES
#define  TPM_CC_Clear                         (TPM_CC)(0x00000126)
#endif
#ifndef CC_ClearControl
#   define CC_ClearControl NO
#endif
#if CC_ClearControl == YES
#define  TPM_CC_ClearControl                  (TPM_CC)(0x00000127)
#endif
#ifndef CC_ClockSet
#   define CC_ClockSet NO
#endif
#if CC_ClockSet == YES
#define  TPM_CC_ClockSet                      (TPM_CC)(0x00000128)
#endif
#ifndef CC_HierarchyChangeAuth
#   define CC_HierarchyChangeAuth NO
#endif
#if CC_HierarchyChangeAuth == YES
#define  TPM_CC_HierarchyChangeAuth           (TPM_CC)(0x00000129)
#endif
#ifndef CC_NV_DefineSpace
#   define CC_NV_DefineSpace NO
#endif
#if CC_NV_DefineSpace == YES
#define  TPM_CC_NV_DefineSpace                (TPM_CC)(0x0000012a)
#endif
#ifndef CC_PCR_Allocate
#   define CC_PCR_Allocate NO
#endif
#if CC_PCR_Allocate == YES
#define  TPM_CC_PCR_Allocate                  (TPM_CC)(0x0000012b)
#endif
#ifndef CC_PCR_SetAuthPolicy
#   define CC_PCR_SetAuthPolicy NO
#endif
#if CC_PCR_SetAuthPolicy == YES
#define  TPM_CC_PCR_SetAuthPolicy             (TPM_CC)(0x0000012c)
#endif
#ifndef CC_PP_Commands
#   define CC_PP_Commands NO
#endif
#if CC_PP_Commands == YES
#define  TPM_CC_PP_Commands                   (TPM_CC)(0x0000012d)
#endif
#ifndef CC_SetPrimaryPolicy
#   define CC_SetPrimaryPolicy NO
#endif
#if CC_SetPrimaryPolicy == YES
#define  TPM_CC_SetPrimaryPolicy              (TPM_CC)(0x0000012e)
#endif
#ifndef CC_FieldUpgradeStart
#   define CC_FieldUpgradeStart NO
#endif
#if CC_FieldUpgradeStart == YES
#define  TPM_CC_FieldUpgradeStart             (TPM_CC)(0x0000012f)
#endif
#ifndef CC_ClockRateAdjust
#   define CC_ClockRateAdjust NO
#endif
#if CC_ClockRateAdjust == YES
#define  TPM_CC_ClockRateAdjust               (TPM_CC)(0x00000130)
#endif
#ifndef CC_CreatePrimary
#   define CC_CreatePrimary NO
#endif
#if CC_CreatePrimary == YES
#define  TPM_CC_CreatePrimary                 (TPM_CC)(0x00000131)
#endif
#ifndef CC_NV_GlobalWriteLock
#   define CC_NV_GlobalWriteLock NO
#endif
#if CC_NV_GlobalWriteLock == YES
#define  TPM_CC_NV_GlobalWriteLock            (TPM_CC)(0x00000132)
#endif
#ifndef CC_GetCommandAuditDigest
#   define CC_GetCommandAuditDigest NO
#endif
#if CC_GetCommandAuditDigest == YES
#define  TPM_CC_GetCommandAuditDigest         (TPM_CC)(0x00000133)
#endif
#ifndef CC_NV_Increment
#   define CC_NV_Increment NO
#endif
#if CC_NV_Increment == YES
#define  TPM_CC_NV_Increment                  (TPM_CC)(0x00000134)
#endif
#ifndef CC_NV_SetBits
#   define CC_NV_SetBits NO
#endif
#if CC_NV_SetBits == YES
#define  TPM_CC_NV_SetBits                    (TPM_CC)(0x00000135)
#endif
#ifndef CC_NV_Extend
#   define CC_NV_Extend NO
#endif
#if CC_NV_Extend == YES
#define  TPM_CC_NV_Extend                     (TPM_CC)(0x00000136)
#endif
#ifndef CC_NV_Write
#   define CC_NV_Write NO
#endif
#if CC_NV_Write == YES
#define  TPM_CC_NV_Write                      (TPM_CC)(0x00000137)
#endif
#ifndef CC_NV_WriteLock
#   define CC_NV_WriteLock NO
#endif
#if CC_NV_WriteLock == YES
#define  TPM_CC_NV_WriteLock                  (TPM_CC)(0x00000138)
#endif
#ifndef CC_DictionaryAttackLockReset
#   define CC_DictionaryAttackLockReset NO
#endif
#if CC_DictionaryAttackLockReset == YES
#define  TPM_CC_DictionaryAttackLockReset     (TPM_CC)(0x00000139)
#endif
#ifndef CC_DictionaryAttackParameters
#   define CC_DictionaryAttackParameters NO
#endif
#if CC_DictionaryAttackParameters == YES
#define  TPM_CC_DictionaryAttackParameters    (TPM_CC)(0x0000013a)
#endif
#ifndef CC_NV_ChangeAuth
#   define CC_NV_ChangeAuth NO
#endif
#if CC_NV_ChangeAuth == YES
#define  TPM_CC_NV_ChangeAuth                 (TPM_CC)(0x0000013b)
#endif
#ifndef CC_PCR_Event
#   define CC_PCR_Event NO
#endif
#if CC_PCR_Event == YES
#define  TPM_CC_PCR_Event                     (TPM_CC)(0x0000013c)
#endif
#ifndef CC_PCR_Reset
#   define CC_PCR_Reset NO
#endif
#if CC_PCR_Reset == YES
#define  TPM_CC_PCR_Reset                     (TPM_CC)(0x0000013d)
#endif
#ifndef CC_SequenceComplete
#   define CC_SequenceComplete NO
#endif
#if CC_SequenceComplete == YES
#define  TPM_CC_SequenceComplete              (TPM_CC)(0x0000013e)
#endif
#ifndef CC_SetAlgorithmSet
#   define CC_SetAlgorithmSet NO
#endif
#if CC_SetAlgorithmSet == YES
#define  TPM_CC_SetAlgorithmSet               (TPM_CC)(0x0000013f)
#endif
#ifndef CC_SetCommandCodeAuditStatus
#   define CC_SetCommandCodeAuditStatus NO
#endif
#if CC_SetCommandCodeAuditStatus == YES
#define  TPM_CC_SetCommandCodeAuditStatus     (TPM_CC)(0x00000140)
#endif
#ifndef CC_FieldUpgradeData
#   define CC_FieldUpgradeData NO
#endif
#if CC_FieldUpgradeData == YES
#define  TPM_CC_FieldUpgradeData              (TPM_CC)(0x00000141)
#endif
#ifndef CC_IncrementalSelfTest
#   define CC_IncrementalSelfTest NO
#endif
#if CC_IncrementalSelfTest == YES
#define  TPM_CC_IncrementalSelfTest           (TPM_CC)(0x00000142)
#endif
#ifndef CC_SelfTest
#   define CC_SelfTest NO
#endif
#if CC_SelfTest == YES
#define  TPM_CC_SelfTest                      (TPM_CC)(0x00000143)
#endif
#ifndef CC_Startup
#   define CC_Startup NO
#endif
#if CC_Startup == YES
#define  TPM_CC_Startup                       (TPM_CC)(0x00000144)
#endif
#ifndef CC_Shutdown
#   define CC_Shutdown NO
#endif
#if CC_Shutdown == YES
#define  TPM_CC_Shutdown                      (TPM_CC)(0x00000145)
#endif
#ifndef CC_StirRandom
#   define CC_StirRandom NO
#endif
#if CC_StirRandom == YES
#define  TPM_CC_StirRandom                    (TPM_CC)(0x00000146)
#endif
#ifndef CC_ActivateCredential
#   define CC_ActivateCredential NO
#endif
#if CC_ActivateCredential == YES
#define  TPM_CC_ActivateCredential            (TPM_CC)(0x00000147)
#endif
#ifndef CC_Certify
#   define CC_Certify NO
#endif
#if CC_Certify == YES
#define  TPM_CC_Certify                       (TPM_CC)(0x00000148)
#endif
#ifndef CC_PolicyNV
#   define CC_PolicyNV NO
#endif
#if CC_PolicyNV == YES
#define  TPM_CC_PolicyNV                      (TPM_CC)(0x00000149)
#endif
#ifndef CC_CertifyCreation
#   define CC_CertifyCreation NO
#endif
#if CC_CertifyCreation == YES
#define  TPM_CC_CertifyCreation               (TPM_CC)(0x0000014a)
#endif
#ifndef CC_Duplicate
#   define CC_Duplicate NO
#endif
#if CC_Duplicate == YES
#define  TPM_CC_Duplicate                     (TPM_CC)(0x0000014b)
#endif
#ifndef CC_GetTime
#   define CC_GetTime NO
#endif
#if CC_GetTime == YES
#define  TPM_CC_GetTime                       (TPM_CC)(0x0000014c)
#endif
#ifndef CC_GetSessionAuditDigest
#   define CC_GetSessionAuditDigest NO
#endif
#if CC_GetSessionAuditDigest == YES
#define  TPM_CC_GetSessionAuditDigest         (TPM_CC)(0x0000014d)
#endif
#ifndef CC_NV_Read
#   define CC_NV_Read NO
#endif
#if CC_NV_Read == YES
#define  TPM_CC_NV_Read                       (TPM_CC)(0x0000014e)
#endif
#ifndef CC_NV_ReadLock
#   define CC_NV_ReadLock NO
#endif
#if CC_NV_ReadLock == YES
#define  TPM_CC_NV_ReadLock                   (TPM_CC)(0x0000014f)
#endif
#ifndef CC_ObjectChangeAuth
#   define CC_ObjectChangeAuth NO
#endif
#if CC_ObjectChangeAuth == YES
#define  TPM_CC_ObjectChangeAuth              (TPM_CC)(0x00000150)
#endif
#ifndef CC_PolicySecret
#   define CC_PolicySecret NO
#endif
#if CC_PolicySecret == YES
#define  TPM_CC_PolicySecret                  (TPM_CC)(0x00000151)
#endif
#ifndef CC_Rewrap
#   define CC_Rewrap NO
#endif
#if CC_Rewrap == YES
#define  TPM_CC_Rewrap                        (TPM_CC)(0x00000152)
#endif
#ifndef CC_Create
#   define CC_Create NO
#endif
#if CC_Create == YES
#define  TPM_CC_Create                        (TPM_CC)(0x00000153)
#endif
#ifndef CC_ECDH_ZGen
#   define CC_ECDH_ZGen NO
#endif
#if CC_ECDH_ZGen == YES
#define  TPM_CC_ECDH_ZGen                     (TPM_CC)(0x00000154)
#endif
#ifndef CC_HMAC
#   define CC_HMAC NO
#endif
#if CC_HMAC == YES
#define  TPM_CC_HMAC                          (TPM_CC)(0x00000155)
#endif
#ifndef CC_Import
#   define CC_Import NO
#endif
#if CC_Import == YES
#define  TPM_CC_Import                        (TPM_CC)(0x00000156)
#endif
#ifndef CC_Load
#   define CC_Load NO
#endif
#if CC_Load == YES
#define  TPM_CC_Load                          (TPM_CC)(0x00000157)
#endif
#ifndef CC_Quote
#   define CC_Quote NO
#endif
#if CC_Quote == YES
#define  TPM_CC_Quote                         (TPM_CC)(0x00000158)
#endif
#ifndef CC_RSA_Decrypt
#   define CC_RSA_Decrypt NO
#endif
#if CC_RSA_Decrypt == YES
#define  TPM_CC_RSA_Decrypt                   (TPM_CC)(0x00000159)
#endif
#ifndef CC_HMAC_Start
#   define CC_HMAC_Start NO
#endif
#if CC_HMAC_Start == YES
#define  TPM_CC_HMAC_Start                    (TPM_CC)(0x0000015b)
#endif
#ifndef CC_SequenceUpdate
#   define CC_SequenceUpdate NO
#endif
#if CC_SequenceUpdate == YES
#define  TPM_CC_SequenceUpdate                (TPM_CC)(0x0000015c)
#endif
#ifndef CC_Sign
#   define CC_Sign NO
#endif
#if CC_Sign == YES
#define  TPM_CC_Sign                          (TPM_CC)(0x0000015d)
#endif
#ifndef CC_Unseal
#   define CC_Unseal NO
#endif
#if CC_Unseal == YES
#define  TPM_CC_Unseal                        (TPM_CC)(0x0000015e)
#endif
#ifndef CC_PolicySigned
#   define CC_PolicySigned NO
#endif
#if CC_PolicySigned == YES
#define  TPM_CC_PolicySigned                  (TPM_CC)(0x00000160)
#endif
#ifndef CC_ContextLoad
#   define CC_ContextLoad NO
#endif
#if CC_ContextLoad == YES
#define  TPM_CC_ContextLoad                   (TPM_CC)(0x00000161)
#endif
#ifndef CC_ContextSave
#   define CC_ContextSave NO
#endif
#if CC_ContextSave == YES
#define  TPM_CC_ContextSave                   (TPM_CC)(0x00000162)
#endif
#ifndef CC_ECDH_KeyGen
#   define CC_ECDH_KeyGen NO
#endif
#if CC_ECDH_KeyGen == YES
#define  TPM_CC_ECDH_KeyGen                   (TPM_CC)(0x00000163)
#endif
#ifndef CC_EncryptDecrypt
#   define CC_EncryptDecrypt NO
#endif
#if CC_EncryptDecrypt == YES
#define  TPM_CC_EncryptDecrypt                (TPM_CC)(0x00000164)
#endif
#ifndef CC_FlushContext
#   define CC_FlushContext NO
#endif
#if CC_FlushContext == YES
#define  TPM_CC_FlushContext                  (TPM_CC)(0x00000165)
#endif
#ifndef CC_LoadExternal
#   define CC_LoadExternal NO
#endif
#if CC_LoadExternal == YES
#define  TPM_CC_LoadExternal                  (TPM_CC)(0x00000167)
#endif
#ifndef CC_MakeCredential
#   define CC_MakeCredential NO
#endif
#if CC_MakeCredential == YES
#define  TPM_CC_MakeCredential                (TPM_CC)(0x00000168)
#endif
#ifndef CC_NV_ReadPublic
#   define CC_NV_ReadPublic NO
#endif
#if CC_NV_ReadPublic == YES
#define  TPM_CC_NV_ReadPublic                 (TPM_CC)(0x00000169)
#endif
#ifndef CC_PolicyAuthorize
#   define CC_PolicyAuthorize NO
#endif
#if CC_PolicyAuthorize == YES
#define  TPM_CC_PolicyAuthorize               (TPM_CC)(0x0000016a)
#endif
#ifndef CC_PolicyAuthValue
#   define CC_PolicyAuthValue NO
#endif
#if CC_PolicyAuthValue == YES
#define  TPM_CC_PolicyAuthValue               (TPM_CC)(0x0000016b)
#endif
#ifndef CC_PolicyCommandCode
#   define CC_PolicyCommandCode NO
#endif
#if CC_PolicyCommandCode == YES
#define  TPM_CC_PolicyCommandCode             (TPM_CC)(0x0000016c)
#endif
#ifndef CC_PolicyCounterTimer
#   define CC_PolicyCounterTimer NO
#endif
#if CC_PolicyCounterTimer == YES
#define  TPM_CC_PolicyCounterTimer            (TPM_CC)(0x0000016d)
#endif
#ifndef CC_PolicyCpHash
#   define CC_PolicyCpHash NO
#endif
#if CC_PolicyCpHash == YES
#define  TPM_CC_PolicyCpHash                  (TPM_CC)(0x0000016e)
#endif
#ifndef CC_PolicyLocality
#   define CC_PolicyLocality NO
#endif
#if CC_PolicyLocality == YES
#define  TPM_CC_PolicyLocality                (TPM_CC)(0x0000016f)
#endif
#ifndef CC_PolicyNameHash
#   define CC_PolicyNameHash NO
#endif
#if CC_PolicyNameHash == YES
#define  TPM_CC_PolicyNameHash                (TPM_CC)(0x00000170)
#endif
#ifndef CC_PolicyOR
#   define CC_PolicyOR NO
#endif
#if CC_PolicyOR == YES
#define  TPM_CC_PolicyOR                      (TPM_CC)(0x00000171)
#endif
#ifndef CC_PolicyTicket
#   define CC_PolicyTicket NO
#endif
#if CC_PolicyTicket == YES
#define  TPM_CC_PolicyTicket                  (TPM_CC)(0x00000172)
#endif
#ifndef CC_ReadPublic
#   define CC_ReadPublic NO
#endif
#if CC_ReadPublic == YES
#define  TPM_CC_ReadPublic                    (TPM_CC)(0x00000173)
#endif
#ifndef CC_RSA_Encrypt
#   define CC_RSA_Encrypt NO
#endif
#if CC_RSA_Encrypt == YES
#define  TPM_CC_RSA_Encrypt                   (TPM_CC)(0x00000174)
#endif
#ifndef CC_StartAuthSession
#   define CC_StartAuthSession NO
#endif
#if CC_StartAuthSession == YES
#define  TPM_CC_StartAuthSession              (TPM_CC)(0x00000176)
#endif
#ifndef CC_VerifySignature
#   define CC_VerifySignature NO
#endif
#if CC_VerifySignature == YES
#define  TPM_CC_VerifySignature               (TPM_CC)(0x00000177)
#endif
#ifndef CC_ECC_Parameters
#   define CC_ECC_Parameters NO
#endif
#if CC_ECC_Parameters == YES
#define  TPM_CC_ECC_Parameters                (TPM_CC)(0x00000178)
#endif
#ifndef CC_FirmwareRead
#   define CC_FirmwareRead NO
#endif
#if CC_FirmwareRead == YES
#define  TPM_CC_FirmwareRead                  (TPM_CC)(0x00000179)
#endif
#ifndef CC_GetCapability
#   define CC_GetCapability NO
#endif
#if CC_GetCapability == YES
#define  TPM_CC_GetCapability                 (TPM_CC)(0x0000017a)
#endif
#ifndef CC_GetRandom
#   define CC_GetRandom NO
#endif
#if CC_GetRandom == YES
#define  TPM_CC_GetRandom                     (TPM_CC)(0x0000017b)
#endif
#ifndef CC_GetTestResult
#   define CC_GetTestResult NO
#endif
#if CC_GetTestResult == YES
#define  TPM_CC_GetTestResult                 (TPM_CC)(0x0000017c)
#endif
#ifndef CC_Hash
#   define CC_Hash NO
#endif
#if CC_Hash == YES
#define  TPM_CC_Hash                          (TPM_CC)(0x0000017d)
#endif
#ifndef CC_PCR_Read
#   define CC_PCR_Read NO
#endif
#if CC_PCR_Read == YES
#define  TPM_CC_PCR_Read                      (TPM_CC)(0x0000017e)
#endif
#ifndef CC_PolicyPCR
#   define CC_PolicyPCR NO
#endif
#if CC_PolicyPCR == YES
#define  TPM_CC_PolicyPCR                     (TPM_CC)(0x0000017f)
#endif
#ifndef CC_PolicyRestart
#   define CC_PolicyRestart NO
#endif
#if CC_PolicyRestart == YES
#define  TPM_CC_PolicyRestart                 (TPM_CC)(0x00000180)
#endif
#ifndef CC_ReadClock
#   define CC_ReadClock NO
#endif
#if CC_ReadClock == YES
#define  TPM_CC_ReadClock                     (TPM_CC)(0x00000181)
#endif
#ifndef CC_PCR_Extend
#   define CC_PCR_Extend NO
#endif
#if CC_PCR_Extend == YES
#define  TPM_CC_PCR_Extend                    (TPM_CC)(0x00000182)
#endif
#ifndef CC_PCR_SetAuthValue
#   define CC_PCR_SetAuthValue NO
#endif
#if CC_PCR_SetAuthValue == YES
#define  TPM_CC_PCR_SetAuthValue              (TPM_CC)(0x00000183)
#endif
#ifndef CC_NV_Certify
#   define CC_NV_Certify NO
#endif
#if CC_NV_Certify == YES
#define  TPM_CC_NV_Certify                    (TPM_CC)(0x00000184)
#endif
#ifndef CC_EventSequenceComplete
#   define CC_EventSequenceComplete NO
#endif
#if CC_EventSequenceComplete == YES
#define  TPM_CC_EventSequenceComplete         (TPM_CC)(0x00000185)
#endif
#ifndef CC_HashSequenceStart
#   define CC_HashSequenceStart NO
#endif
#if CC_HashSequenceStart == YES
#define  TPM_CC_HashSequenceStart             (TPM_CC)(0x00000186)
#endif
#ifndef CC_PolicyPhysicalPresence
#   define CC_PolicyPhysicalPresence NO
#endif
#if CC_PolicyPhysicalPresence == YES
#define  TPM_CC_PolicyPhysicalPresence        (TPM_CC)(0x00000187)
#endif
#ifndef CC_PolicyDuplicationSelect
#   define CC_PolicyDuplicationSelect NO
#endif
#if CC_PolicyDuplicationSelect == YES
#define  TPM_CC_PolicyDuplicationSelect       (TPM_CC)(0x00000188)
#endif
#ifndef CC_PolicyGetDigest
#   define CC_PolicyGetDigest NO
#endif
#if CC_PolicyGetDigest == YES
#define  TPM_CC_PolicyGetDigest               (TPM_CC)(0x00000189)
#endif
#ifndef CC_TestParms
#   define CC_TestParms NO
#endif
#if CC_TestParms == YES
#define  TPM_CC_TestParms                     (TPM_CC)(0x0000018a)
#endif
#ifndef CC_Commit
#   define CC_Commit NO
#endif
#if CC_Commit == YES
#define  TPM_CC_Commit                        (TPM_CC)(0x0000018b)
#endif
#ifndef CC_PolicyPassword
#   define CC_PolicyPassword NO
#endif
#if CC_PolicyPassword == YES
#define  TPM_CC_PolicyPassword                (TPM_CC)(0x0000018c)
#endif
#ifndef CC_ZGen_2Phase
#   define CC_ZGen_2Phase NO
#endif
#if CC_ZGen_2Phase == YES
#define  TPM_CC_ZGen_2Phase                   (TPM_CC)(0x0000018d)
#endif
#ifndef CC_EC_Ephemeral
#   define CC_EC_Ephemeral NO
#endif
#if CC_EC_Ephemeral == YES
#define  TPM_CC_EC_Ephemeral                  (TPM_CC)(0x0000018e)
#endif
#ifndef CC_PolicyNvWritten
#   define CC_PolicyNvWritten NO
#endif
#if CC_PolicyNvWritten == YES
#define  TPM_CC_PolicyNvWritten               (TPM_CC)(0x0000018f)
#endif
#ifndef CC_EncryptDecrypt2
#define CC_EncryptDecrypt2 NO
#endif
#if CC_EncryptDecrypt2 == YES
#define  TPM_CC_EncryptDecrypt2               (TPM_CC)(0x00000193)
#endif

#ifndef CC_AC_GetCapability
#define CC_AC_GetCapability NO
#endif
#if CC_AC_GetCapability == YES
#define  TPM_CC_AC_GetCapability              (TPM_CC)(0x00000194)
#endif

#ifndef CC_AC_Send
#define CC_AC_Send NO
#endif
#if CC_AC_Send == YES
#define  TPM_CC_AC_Send                       (TPM_CC)(0x00000195)
#endif

#ifndef CC_Policy_AC_SendSelect
#define CC_Policy_AC_SendSelect NO
#endif
#if CC_Policy_AC_SendSelect == YES
#define  TPM_CC_Policy_AC_SendSelect          (TPM_CC)(0x00000196)
#endif

#define  TPM_CC_LAST                          (TPM_CC)(0x00000196)
#ifndef CC_Vendor_TCG_Test
#   define CC_Vendor_TCG_Test NO
#endif
#if CC_Vendor_TCG_Test == YES
#define  TPM_CC_Vendor_TCG_Test               (TPM_CC)(0x20000000)
#endif

#ifndef  COMPRESSED_LISTS
#define ADD_FILL    1
#else
#define ADD_FILL   0
#endif

// Size the array of library commands based on whether or not the array is packed (only defined
// commands) or dense (having entries for unimplemented commands)

#define LIBRARY_COMMAND_ARRAY_SIZE       (0				\
					  + (ADD_FILL || CC_NV_UndefineSpaceSpecial)    /* 0x0000011f */ \
					  + (ADD_FILL || CC_EvictControl)               /* 0x00000120 */ \
					  + (ADD_FILL || CC_HierarchyControl)           /* 0x00000121 */ \
					  + (ADD_FILL || CC_NV_UndefineSpace)           /* 0x00000122 */ \
					  + ADD_FILL                                             /* 0x00000123 */ \
					  + (ADD_FILL || CC_ChangeEPS)                  /* 0x00000124 */ \
					  + (ADD_FILL || CC_ChangePPS)                  /* 0x00000125 */ \
					  + (ADD_FILL || CC_Clear)                      /* 0x00000126 */ \
					  + (ADD_FILL || CC_ClearControl)               /* 0x00000127 */ \
					  + (ADD_FILL || CC_ClockSet)                   /* 0x00000128 */ \
					  + (ADD_FILL || CC_HierarchyChangeAuth)        /* 0x00000129 */ \
					  + (ADD_FILL || CC_NV_DefineSpace)             /* 0x0000012a */ \
					  + (ADD_FILL || CC_PCR_Allocate)               /* 0x0000012b */ \
					  + (ADD_FILL || CC_PCR_SetAuthPolicy)          /* 0x0000012c */ \
					  + (ADD_FILL || CC_PP_Commands)                /* 0x0000012d */ \
					  + (ADD_FILL || CC_SetPrimaryPolicy)           /* 0x0000012e */ \
					  + (ADD_FILL || CC_FieldUpgradeStart)          /* 0x0000012f */ \
					  + (ADD_FILL || CC_ClockRateAdjust)            /* 0x00000130 */ \
					  + (ADD_FILL || CC_CreatePrimary)              /* 0x00000131 */ \
					  + (ADD_FILL || CC_NV_GlobalWriteLock)         /* 0x00000132 */ \
					  + (ADD_FILL || CC_GetCommandAuditDigest)      /* 0x00000133 */ \
					  + (ADD_FILL || CC_NV_Increment)               /* 0x00000134 */ \
					  + (ADD_FILL || CC_NV_SetBits)                 /* 0x00000135 */ \
					  + (ADD_FILL || CC_NV_Extend)                  /* 0x00000136 */ \
					  + (ADD_FILL || CC_NV_Write)                   /* 0x00000137 */ \
					  + (ADD_FILL || CC_NV_WriteLock)               /* 0x00000138 */ \
					  + (ADD_FILL || CC_DictionaryAttackLockReset)  /* 0x00000139 */ \
					  + (ADD_FILL || CC_DictionaryAttackParameters) /* 0x0000013a */ \
					  + (ADD_FILL || CC_NV_ChangeAuth)              /* 0x0000013b */ \
					  + (ADD_FILL || CC_PCR_Event)                  /* 0x0000013c */ \
					  + (ADD_FILL || CC_PCR_Reset)                  /* 0x0000013d */ \
					  + (ADD_FILL || CC_SequenceComplete)           /* 0x0000013e */ \
					  + (ADD_FILL || CC_SetAlgorithmSet)            /* 0x0000013f */ \
					  + (ADD_FILL || CC_SetCommandCodeAuditStatus)  /* 0x00000140 */ \
					  + (ADD_FILL || CC_FieldUpgradeData)           /* 0x00000141 */ \
					  + (ADD_FILL || CC_IncrementalSelfTest)        /* 0x00000142 */ \
					  + (ADD_FILL || CC_SelfTest)                   /* 0x00000143 */ \
					  + (ADD_FILL || CC_Startup)                    /* 0x00000144 */ \
					  + (ADD_FILL || CC_Shutdown)                   /* 0x00000145 */ \
					  + (ADD_FILL || CC_StirRandom)                 /* 0x00000146 */ \
					  + (ADD_FILL || CC_ActivateCredential)         /* 0x00000147 */ \
					  + (ADD_FILL || CC_Certify)                    /* 0x00000148 */ \
					  + (ADD_FILL || CC_PolicyNV)                   /* 0x00000149 */ \
					  + (ADD_FILL || CC_CertifyCreation)            /* 0x0000014a */ \
					  + (ADD_FILL || CC_Duplicate)                  /* 0x0000014b */ \
					  + (ADD_FILL || CC_GetTime)                    /* 0x0000014c */ \
					  + (ADD_FILL || CC_GetSessionAuditDigest)      /* 0x0000014d */ \
					  + (ADD_FILL || CC_NV_Read)                    /* 0x0000014e */ \
					  + (ADD_FILL || CC_NV_ReadLock)                /* 0x0000014f */ \
					  + (ADD_FILL || CC_ObjectChangeAuth)           /* 0x00000150 */ \
					  + (ADD_FILL || CC_PolicySecret)               /* 0x00000151 */ \
					  + (ADD_FILL || CC_Rewrap)                     /* 0x00000152 */ \
					  + (ADD_FILL || CC_Create)                     /* 0x00000153 */ \
					  + (ADD_FILL || CC_ECDH_ZGen)                  /* 0x00000154 */ \
					  + (ADD_FILL || CC_HMAC)                       /* 0x00000155 */ \
					  + (ADD_FILL || CC_Import)                     /* 0x00000156 */ \
					  + (ADD_FILL || CC_Load)                       /* 0x00000157 */ \
					  + (ADD_FILL || CC_Quote)                      /* 0x00000158 */ \
					  + (ADD_FILL || CC_RSA_Decrypt)                /* 0x00000159 */ \
					  + ADD_FILL                                             /* 0x0000015a */ \
					  + (ADD_FILL || CC_HMAC_Start)                 /* 0x0000015b */ \
					  + (ADD_FILL || CC_SequenceUpdate)             /* 0x0000015c */ \
					  + (ADD_FILL || CC_Sign)                       /* 0x0000015d */ \
					  + (ADD_FILL || CC_Unseal)                     /* 0x0000015e */ \
					  + ADD_FILL                                             /* 0x0000015f */ \
					  + (ADD_FILL || CC_PolicySigned)               /* 0x00000160 */ \
					  + (ADD_FILL || CC_ContextLoad)                /* 0x00000161 */ \
					  + (ADD_FILL || CC_ContextSave)                /* 0x00000162 */ \
					  + (ADD_FILL || CC_ECDH_KeyGen)                /* 0x00000163 */ \
					  + (ADD_FILL || CC_EncryptDecrypt)             /* 0x00000164 */ \
					  + (ADD_FILL || CC_FlushContext)               /* 0x00000165 */ \
					  + ADD_FILL                                             /* 0x00000166 */ \
					  + (ADD_FILL || CC_LoadExternal)               /* 0x00000167 */ \
					  + (ADD_FILL || CC_MakeCredential)             /* 0x00000168 */ \
					  + (ADD_FILL || CC_NV_ReadPublic)              /* 0x00000169 */ \
					  + (ADD_FILL || CC_PolicyAuthorize)            /* 0x0000016a */ \
					  + (ADD_FILL || CC_PolicyAuthValue)            /* 0x0000016b */ \
					  + (ADD_FILL || CC_PolicyCommandCode)          /* 0x0000016c */ \
					  + (ADD_FILL || CC_PolicyCounterTimer)         /* 0x0000016d */ \
					  + (ADD_FILL || CC_PolicyCpHash)               /* 0x0000016e */ \
					  + (ADD_FILL || CC_PolicyLocality)             /* 0x0000016f */ \
					  + (ADD_FILL || CC_PolicyNameHash)             /* 0x00000170 */ \
					  + (ADD_FILL || CC_PolicyOR)                   /* 0x00000171 */ \
					  + (ADD_FILL || CC_PolicyTicket)               /* 0x00000172 */ \
					  + (ADD_FILL || CC_ReadPublic)                 /* 0x00000173 */ \
					  + (ADD_FILL || CC_RSA_Encrypt)                /* 0x00000174 */ \
					  + ADD_FILL                                             /* 0x00000175 */ \
					  + (ADD_FILL || CC_StartAuthSession)           /* 0x00000176 */ \
					  + (ADD_FILL || CC_VerifySignature)            /* 0x00000177 */ \
					  + (ADD_FILL || CC_ECC_Parameters)             /* 0x00000178 */ \
					  + (ADD_FILL || CC_FirmwareRead)               /* 0x00000179 */ \
					  + (ADD_FILL || CC_GetCapability)              /* 0x0000017a */ \
					  + (ADD_FILL || CC_GetRandom)                  /* 0x0000017b */ \
					  + (ADD_FILL || CC_GetTestResult)              /* 0x0000017c */ \
					  + (ADD_FILL || CC_Hash)                       /* 0x0000017d */ \
					  + (ADD_FILL || CC_PCR_Read)                   /* 0x0000017e */ \
					  + (ADD_FILL || CC_PolicyPCR)                  /* 0x0000017f */ \
					  + (ADD_FILL || CC_PolicyRestart)              /* 0x00000180 */ \
					  + (ADD_FILL || CC_ReadClock)                  /* 0x00000181 */ \
					  + (ADD_FILL || CC_PCR_Extend)                 /* 0x00000182 */ \
					  + (ADD_FILL || CC_PCR_SetAuthValue)           /* 0x00000183 */ \
					  + (ADD_FILL || CC_NV_Certify)                 /* 0x00000184 */ \
					  + (ADD_FILL || CC_EventSequenceComplete)      /* 0x00000185 */ \
					  + (ADD_FILL || CC_HashSequenceStart)          /* 0x00000186 */ \
					  + (ADD_FILL || CC_PolicyPhysicalPresence)     /* 0x00000187 */ \
					  + (ADD_FILL || CC_PolicyDuplicationSelect)    /* 0x00000188 */ \
					  + (ADD_FILL || CC_PolicyGetDigest)            /* 0x00000189 */ \
					  + (ADD_FILL || CC_TestParms)                  /* 0x0000018a */ \
					  + (ADD_FILL || CC_Commit)                     /* 0x0000018b */ \
					  + (ADD_FILL || CC_PolicyPassword)             /* 0x0000018c */ \
					  + (ADD_FILL || CC_ZGen_2Phase)                /* 0x0000018d */ \
					  + (ADD_FILL || CC_EC_Ephemeral)               /* 0x0000018e */ \
					  + (ADD_FILL || CC_PolicyNvWritten)            /* 0x0000018f */ \
                                          + ADD_FILL                                    /* 0x00000190 */ \
                                          + ADD_FILL                                    /* 0x00000191 */ \
                                          + ADD_FILL                                    /* 0x00000192 */ \
                                          + ADD_FILL                                    /* 0x00000193 */ \
					  )

#define VENDOR_COMMAND_ARRAY_SIZE   ( 0					\
				      + CC_Vendor_TCG_Test		\
				      )

#define COMMAND_COUNT							\
    (LIBRARY_COMMAND_ARRAY_SIZE + VENDOR_COMMAND_ARRAY_SIZE)


#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#define MAX_HASH_BLOCK_SIZE  (						\
			      MAX(ALG_SHA1 * SHA1_BLOCK_SIZE,		\
				  MAX(ALG_SHA256 * SHA256_BLOCK_SIZE,	\
				      MAX(ALG_SHA384 * SHA384_BLOCK_SIZE, \
					  MAX(ALG_SM3_256 * SM3_256_BLOCK_SIZE, \
					      MAX(ALG_SHA512 * SHA512_BLOCK_SIZE, \
						  0 ))))))

#define MAX_DIGEST_SIZE      (						\
			      MAX(ALG_SHA1 * SHA1_DIGEST_SIZE,		\
				  MAX(ALG_SHA256 * SHA256_DIGEST_SIZE,	\
				      MAX(ALG_SHA384 * SHA384_DIGEST_SIZE, \
					  MAX(ALG_SM3_256 * SM3_256_DIGEST_SIZE, \
					      MAX(ALG_SHA512 * SHA512_DIGEST_SIZE, \
						  0 ))))))

#if MAX_DIGEST_SIZE == 0 || MAX_HASH_BLOCK_SIZE == 0
#error "Hash data not valid"
#endif

#define HASH_COUNT (ALG_SHA1+ALG_SHA256+ALG_SHA384+ALG_SM3_256+ALG_SHA512)

TPM2B_TYPE(MAX_HASH_BLOCK, MAX_HASH_BLOCK_SIZE);

// Following typedef is for some old code

typedef TPM2B_MAX_HASH_BLOCK    TPM2B_HASH_BLOCK;

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef ALG_CAMELLIA
#   define ALG_CAMELLIA         NO
#endif

#ifndef MAX_CAMELLIA_KEY_BITS
#   define      MAX_CAMELLIA_KEY_BITS  0
#   define      MAX_CAMELLIA_BLOCK_SIZE_BYTES 0
#endif

#ifndef ALG_SM4
#   define ALG_SM4         NO
#endif

#ifndef MAX_SM4_KEY_BITS
#   define      MAX_SM4_KEY_BITS  0
#   define      MAX_SM4_BLOCK_SIZE_BYTES 0
#endif

#ifndef ALG_AES
#   define ALG_AES         NO
#endif

#ifndef MAX_AES_KEY_BITS
#   define      MAX_AES_KEY_BITS  0
#   define      MAX_AES_BLOCK_SIZE_BYTES 0
#endif

#define MAX_SYM_KEY_BITS (						\
			  MAX(MAX_CAMELLIA_KEY_BITS * ALG_CAMELLIA,	\
			      MAX(MAX_SM4_KEY_BITS * ALG_SM4,		\
				  MAX(MAX_AES_KEY_BITS * ALG_AES,	\
				      0))))
#define MAX_SYM_KEY_BYTES ((MAX_SYM_KEY_BITS + 7) / 8)
#define MAX_SYM_BLOCK_SIZE  (						\
			     MAX(MAX_CAMELLIA_BLOCK_SIZE_BYTES * ALG_CAMELLIA, \
				 MAX(MAX_SM4_BLOCK_SIZE_BYTES * ALG_SM4, \
				     MAX(MAX_AES_BLOCK_SIZE_BYTES * ALG_AES, \
					 0))))
#if MAX_SYM_KEY_BITS == 0 || MAX_SYM_BLOCK_SIZE == 0
#   error Bad size for MAX_SYM_KEY_BITS or MAX_SYM_BLOCK_SIZE
#endif

// Define the 2B structure for a seed
TPM2B_TYPE(SEED, PRIMARY_SEED_SIZE);

#endif  // _IMPLEMENTATION_H_
