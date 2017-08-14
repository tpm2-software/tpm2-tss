//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

// From TPM 2.0 Part 2: Table 4 - Defines for Logic Values
#define  YES      1
#define  NO       0

// From Vendor-Specific: Table 1 - Defines for Processor Values

#define BIG_ENDIAN_TPM       	NO	/*  to YES or NO according to the processor */
#define LITTLE_ENDIAN_TPM	YES	/*  to YES or NO according to the processor */
#define NO_AUTO_ALIGN		NO	/*  to YES if the processor does not allow unaligned accesses */

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

// From TCG Algorithm Registry: Table 3 - Definition of TPM_ALG_ID Constants

typedef  UINT16             TPM_ALG_ID;
#define  TPM_ALG_ERROR               0x0000
#define  TPM_ALG_RSA                 0x0001
#define  TPM_ALG_SHA                 0x0004
#define  TPM_ALG_SHA1                0x0004
#define  TPM_ALG_HMAC                0x0005
#define  TPM_ALG_AES                 0x0006
#define  TPM_ALG_MGF1                0x0007
#define  TPM_ALG_KEYEDHASH           0x0008
#define  TPM_ALG_XOR                 0x000A
#define  TPM_ALG_SHA256              0x000B
#define  TPM_ALG_SHA384              0x000C
#define  TPM_ALG_SHA512              0x000D
#define  TPM_ALG_NULL                0x0010
#define  TPM_ALG_SM3_256             0x0012
#define  TPM_ALG_SM4                 0x0013
#define  TPM_ALG_RSASSA              0x0014
#define  TPM_ALG_RSAES               0x0015
#define  TPM_ALG_RSAPSS              0x0016
#define  TPM_ALG_OAEP                0x0017
#define  TPM_ALG_ECDSA               0x0018
#define  TPM_ALG_ECDH                0x0019
#define  TPM_ALG_ECDAA               0x001A
#define  TPM_ALG_SM2                 0x001B
#define  TPM_ALG_ECSCHNORR           0x001C
#define  TPM_ALG_ECMQV               0x001D
#define  TPM_ALG_KDF1_SP800_56A      0x0020
#define  TPM_ALG_KDF2                0x0021
#define  TPM_ALG_KDF1_SP800_108      0x0022
#define  TPM_ALG_ECC                 0x0023
#define  TPM_ALG_SYMCIPHER           0x0025
#define  TPM_ALG_CAMELLIA            0x0026
#define  TPM_ALG_CTR                 0x0040
#define  TPM_ALG_SHA3_256            0x0027
#define  TPM_ALG_SHA3_384            0x0028
#define  TPM_ALG_SHA3_512            0x0029
#define  TPM_ALG_OFB                 0x0041
#define  TPM_ALG_CBC                 0x0042
#define  TPM_ALG_CFB                 0x0043
#define  TPM_ALG_ECB                 0x0044
#define  TPM_ALG_FIRST               0x0001
#define  TPM_ALG_LAST                0x0044
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

#define  TPM_CC_NV_UndefineSpaceSpecial       (TPM_CC)(0x0000011f)
#define TPM_CC_FIRST TPM_CC_NV_UndefineSpaceSpecial
#define  TPM_CC_EvictControl                  (TPM_CC)(0x00000120)
#define  TPM_CC_HierarchyControl              (TPM_CC)(0x00000121)
#define  TPM_CC_NV_UndefineSpace              (TPM_CC)(0x00000122)
#define  TPM_CC_ChangeEPS                     (TPM_CC)(0x00000124)
#define  TPM_CC_ChangePPS                     (TPM_CC)(0x00000125)
#define  TPM_CC_Clear                         (TPM_CC)(0x00000126)
#define  TPM_CC_ClearControl                  (TPM_CC)(0x00000127)
#define  TPM_CC_ClockSet                      (TPM_CC)(0x00000128)
#define  TPM_CC_HierarchyChangeAuth           (TPM_CC)(0x00000129)
#define  TPM_CC_NV_DefineSpace                (TPM_CC)(0x0000012a)
#define  TPM_CC_PCR_Allocate                  (TPM_CC)(0x0000012b)
#define  TPM_CC_PCR_SetAuthPolicy             (TPM_CC)(0x0000012c)
#define  TPM_CC_PP_Commands                   (TPM_CC)(0x0000012d)
#define  TPM_CC_SetPrimaryPolicy              (TPM_CC)(0x0000012e)
#define  TPM_CC_FieldUpgradeStart             (TPM_CC)(0x0000012f)
#define  TPM_CC_ClockRateAdjust               (TPM_CC)(0x00000130)
#define  TPM_CC_CreatePrimary                 (TPM_CC)(0x00000131)
#define  TPM_CC_NV_GlobalWriteLock            (TPM_CC)(0x00000132)
#define  TPM_CC_GetCommandAuditDigest         (TPM_CC)(0x00000133)
#define  TPM_CC_NV_Increment                  (TPM_CC)(0x00000134)
#define  TPM_CC_NV_SetBits                    (TPM_CC)(0x00000135)
#define  TPM_CC_NV_Extend                     (TPM_CC)(0x00000136)
#define  TPM_CC_NV_Write                      (TPM_CC)(0x00000137)
#define  TPM_CC_NV_WriteLock                  (TPM_CC)(0x00000138)
#define  TPM_CC_DictionaryAttackLockReset     (TPM_CC)(0x00000139)
#define  TPM_CC_DictionaryAttackParameters    (TPM_CC)(0x0000013a)
#define  TPM_CC_NV_ChangeAuth                 (TPM_CC)(0x0000013b)
#define  TPM_CC_PCR_Event                     (TPM_CC)(0x0000013c)
#define  TPM_CC_PCR_Reset                     (TPM_CC)(0x0000013d)
#define  TPM_CC_SequenceComplete              (TPM_CC)(0x0000013e)
#define  TPM_CC_SetAlgorithmSet               (TPM_CC)(0x0000013f)
#define  TPM_CC_SetCommandCodeAuditStatus     (TPM_CC)(0x00000140)
#define  TPM_CC_FieldUpgradeData              (TPM_CC)(0x00000141)
#define  TPM_CC_IncrementalSelfTest           (TPM_CC)(0x00000142)
#define  TPM_CC_SelfTest                      (TPM_CC)(0x00000143)
#define  TPM_CC_Startup                       (TPM_CC)(0x00000144)
#define  TPM_CC_Shutdown                      (TPM_CC)(0x00000145)
#define  TPM_CC_StirRandom                    (TPM_CC)(0x00000146)
#define  TPM_CC_ActivateCredential            (TPM_CC)(0x00000147)
#define  TPM_CC_Certify                       (TPM_CC)(0x00000148)
#define  TPM_CC_PolicyNV                      (TPM_CC)(0x00000149)
#define  TPM_CC_CertifyCreation               (TPM_CC)(0x0000014a)
#define  TPM_CC_Duplicate                     (TPM_CC)(0x0000014b)
#define  TPM_CC_GetTime                       (TPM_CC)(0x0000014c)
#define  TPM_CC_GetSessionAuditDigest         (TPM_CC)(0x0000014d)
#define  TPM_CC_NV_Read                       (TPM_CC)(0x0000014e)
#define  TPM_CC_NV_ReadLock                   (TPM_CC)(0x0000014f)
#define  TPM_CC_ObjectChangeAuth              (TPM_CC)(0x00000150)
#define  TPM_CC_PolicySecret                  (TPM_CC)(0x00000151)
#define  TPM_CC_Rewrap                        (TPM_CC)(0x00000152)
#define  TPM_CC_Create                        (TPM_CC)(0x00000153)
#define  TPM_CC_ECDH_ZGen                     (TPM_CC)(0x00000154)
#define  TPM_CC_HMAC                          (TPM_CC)(0x00000155)
#define  TPM_CC_Import                        (TPM_CC)(0x00000156)
#define  TPM_CC_Load                          (TPM_CC)(0x00000157)
#define  TPM_CC_Quote                         (TPM_CC)(0x00000158)
#define  TPM_CC_RSA_Decrypt                   (TPM_CC)(0x00000159)
#define  TPM_CC_HMAC_Start                    (TPM_CC)(0x0000015b)
#define  TPM_CC_SequenceUpdate                (TPM_CC)(0x0000015c)
#define  TPM_CC_Sign                          (TPM_CC)(0x0000015d)
#define  TPM_CC_Unseal                        (TPM_CC)(0x0000015e)
#define  TPM_CC_PolicySigned                  (TPM_CC)(0x00000160)
#define  TPM_CC_ContextLoad                   (TPM_CC)(0x00000161)
#define  TPM_CC_ContextSave                   (TPM_CC)(0x00000162)
#define  TPM_CC_ECDH_KeyGen                   (TPM_CC)(0x00000163)
#define  TPM_CC_EncryptDecrypt                (TPM_CC)(0x00000164)
#define  TPM_CC_FlushContext                  (TPM_CC)(0x00000165)
#define  TPM_CC_LoadExternal                  (TPM_CC)(0x00000167)
#define  TPM_CC_MakeCredential                (TPM_CC)(0x00000168)
#define  TPM_CC_NV_ReadPublic                 (TPM_CC)(0x00000169)
#define  TPM_CC_PolicyAuthorize               (TPM_CC)(0x0000016a)
#define  TPM_CC_PolicyAuthValue               (TPM_CC)(0x0000016b)
#define  TPM_CC_PolicyCommandCode             (TPM_CC)(0x0000016c)
#define  TPM_CC_PolicyCounterTimer            (TPM_CC)(0x0000016d)
#define  TPM_CC_PolicyCpHash                  (TPM_CC)(0x0000016e)
#define  TPM_CC_PolicyLocality                (TPM_CC)(0x0000016f)
#define  TPM_CC_PolicyNameHash                (TPM_CC)(0x00000170)
#define  TPM_CC_PolicyOR                      (TPM_CC)(0x00000171)
#define  TPM_CC_PolicyTicket                  (TPM_CC)(0x00000172)
#define  TPM_CC_ReadPublic                    (TPM_CC)(0x00000173)
#define  TPM_CC_RSA_Encrypt                   (TPM_CC)(0x00000174)
#define  TPM_CC_StartAuthSession              (TPM_CC)(0x00000176)
#define  TPM_CC_VerifySignature               (TPM_CC)(0x00000177)
#define  TPM_CC_ECC_Parameters                (TPM_CC)(0x00000178)
#define  TPM_CC_FirmwareRead                  (TPM_CC)(0x00000179)
#define  TPM_CC_GetCapability                 (TPM_CC)(0x0000017a)
#define  TPM_CC_GetRandom                     (TPM_CC)(0x0000017b)
#define  TPM_CC_GetTestResult                 (TPM_CC)(0x0000017c)
#define  TPM_CC_Hash                          (TPM_CC)(0x0000017d)
#define  TPM_CC_PCR_Read                      (TPM_CC)(0x0000017e)
#define  TPM_CC_PolicyPCR                     (TPM_CC)(0x0000017f)
#define  TPM_CC_PolicyRestart                 (TPM_CC)(0x00000180)
#define  TPM_CC_ReadClock                     (TPM_CC)(0x00000181)
#define  TPM_CC_PCR_Extend                    (TPM_CC)(0x00000182)
#define  TPM_CC_PCR_SetAuthValue              (TPM_CC)(0x00000183)
#define  TPM_CC_NV_Certify                    (TPM_CC)(0x00000184)
#define  TPM_CC_EventSequenceComplete         (TPM_CC)(0x00000185)
#define  TPM_CC_HashSequenceStart             (TPM_CC)(0x00000186)
#define  TPM_CC_PolicyPhysicalPresence        (TPM_CC)(0x00000187)
#define  TPM_CC_PolicyDuplicationSelect       (TPM_CC)(0x00000188)
#define  TPM_CC_PolicyGetDigest               (TPM_CC)(0x00000189)
#define  TPM_CC_TestParms                     (TPM_CC)(0x0000018a)
#define  TPM_CC_Commit                        (TPM_CC)(0x0000018b)
#define  TPM_CC_PolicyPassword                (TPM_CC)(0x0000018c)
#define  TPM_CC_ZGen_2Phase                   (TPM_CC)(0x0000018d)
#define  TPM_CC_EC_Ephemeral                  (TPM_CC)(0x0000018e)
#define  TPM_CC_PolicyNvWritten               (TPM_CC)(0x0000018f)
#define  TPM_CC_LAST                          (TPM_CC)(0x0000018f)
#define  TPM_CC_Vendor_TCG_Test               (TPM_CC)(0x20000000)

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#define MAX_HASH_BLOCK_SIZE  (						\
			      MAX(SHA1_BLOCK_SIZE,		\
				  MAX(SHA256_BLOCK_SIZE,	\
				      MAX(SHA384_BLOCK_SIZE, \
					  MAX(SM3_256_BLOCK_SIZE, \
					      MAX(SHA512_BLOCK_SIZE, \
						  0 ))))))

#define MAX_DIGEST_SIZE      (						\
			      MAX(SHA1_DIGEST_SIZE,		\
				  MAX(SHA256_DIGEST_SIZE,	\
				      MAX(SHA384_DIGEST_SIZE, \
					  MAX(SM3_256_DIGEST_SIZE, \
					      MAX(SHA512_DIGEST_SIZE, \
						  0 ))))))

#if MAX_DIGEST_SIZE == 0 || MAX_HASH_BLOCK_SIZE == 0
#error "Hash data not valid"
#endif

#define HASH_COUNT 5

#define MAX_SYM_KEY_BITS (						\
			  MAX(MAX_CAMELLIA_KEY_BITS,	\
			      MAX(MAX_SM4_KEY_BITS,		\
				  MAX(MAX_AES_KEY_BITS,	\
				      0))))
#define MAX_SYM_KEY_BYTES ((MAX_SYM_KEY_BITS + 7) / 8)
#define MAX_SYM_BLOCK_SIZE  (						\
			     MAX(MAX_CAMELLIA_BLOCK_SIZE_BYTES, \
				 MAX(MAX_SM4_BLOCK_SIZE_BYTES, \
				     MAX(MAX_AES_BLOCK_SIZE_BYTES, \
					 0))))
#if MAX_SYM_KEY_BITS == 0 || MAX_SYM_BLOCK_SIZE == 0
#   error Bad size for MAX_SYM_KEY_BITS or MAX_SYM_BLOCK_SIZE
#endif

#endif  // _IMPLEMENTATION_H_
