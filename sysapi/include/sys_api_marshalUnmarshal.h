//**********************************************************************;
// Copyright (c) 2015, 2017 Intel Corporation
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

#ifndef TSS2_SYS_API_MARSHAL_UNMARSHAL_H
#define TSS2_SYS_API_MARSHAL_UNMARSHAL_H

void Marshal_Simple_TPM2B( UINT8 *inBuffPtr, UINT32 maxCommandSize, UINT8 **nextData, TPM2B *value, TSS2_RC *rval );
void Unmarshal_Simple_TPM2B( UINT8 *outBuffPtr, UINT32 maxResponseSize, UINT8 **nextData, TPM2B *value, TSS2_RC *rval );
void Unmarshal_Simple_TPM2B_NoSizeCheck( UINT8 *outBuffPtr, UINT32 maxResponseSize, UINT8 **nextData, TPM2B *value, TSS2_RC *rval );
void Marshal_UINT64( UINT8 *inBuffPtr, UINT32 maxCommandSize, UINT8 **nextData, UINT64 value, TSS2_RC *rval );
void Marshal_UINT32( UINT8 *inBuffPtr, UINT32 maxCommandSize, UINT8 **nextData, UINT32 value, TSS2_RC *rval );
void Marshal_UINT16( UINT8 *inBuffPtr, UINT32 maxCommandSize, UINT8 **nextData, UINT16 value, TSS2_RC *rval );
void Marshal_UINT8( UINT8 *inBuffPtr, UINT32 maxCommandSize, UINT8 **nextData, UINT8 value, TSS2_RC *rval );
void Unmarshal_UINT64( UINT8 *outBuffPtr, UINT32 maxResponseSize, UINT8 **nextData, UINT64 *value, TSS2_RC *rval );
void Unmarshal_UINT32( UINT8 *outBuffPtr, UINT32 maxResponseSize, UINT8 **nextData, UINT32 *value, TSS2_RC *rval );
void Unmarshal_UINT16( UINT8 *outBuffPtr, UINT32 maxResponseSize, UINT8 **nextData, UINT16 *value, TSS2_RC *rval );
void Unmarshal_UINT8( UINT8 *outBuffPtr, UINT32 maxResponseSize, UINT8 **nextData, UINT8 *value, TSS2_RC *rval );
void Marshal_TPMS_EMPTY( TSS2_SYS_CONTEXT *sysContext, TPMS_EMPTY *empty );
void Unmarshal_TPMS_EMPTY( TSS2_SYS_CONTEXT *sysContext, TPMS_EMPTY *empty );

TSS2_RC CheckOverflow( UINT8 *buffer, UINT32 bufferSize, UINT8 *nextData, UINT32 size );
TSS2_RC CheckDataPointers( UINT8 *buffer, UINT8 **nextData );


// Macro for unmarshalling/marshalling in SYSAPI code.  We needed access to generic base functions in resource manager and
// other places
#define UNMARSHAL_SIMPLE_TPM2B( sysContext, value ) \
    Unmarshal_Simple_TPM2B( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &( SYS_CONTEXT->nextData ), value, &(SYS_CONTEXT->rval ) )

#define UNMARSHAL_SIMPLE_TPM2B_NO_SIZE_CHECK( sysContext, value ) \
    Unmarshal_Simple_TPM2B_NoSizeCheck( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &( SYS_CONTEXT->nextData ), value, &(SYS_CONTEXT->rval ) )

#define UNMARSHAL_TPMS_CONTEXT( sysContext, value ) \
    Unmarshal_TPMS_CONTEXT( SYS_CONTEXT->tpmOutBuffPtr, SYS_CONTEXT->maxResponseSize, &( SYS_CONTEXT->nextData ), value, &(SYS_CONTEXT->rval ) )

#define MARSHAL_SIMPLE_TPM2B( sysContext, value ) \
    Marshal_Simple_TPM2B( SYS_CONTEXT->tpmInBuffPtr, SYS_CONTEXT->maxCommandSize, &( SYS_CONTEXT->nextData ), value, &(SYS_CONTEXT->rval ) )

#define Marshal_INT8( sysContext, var ) Marshal_int8_t( sysContext, (int8_t *)var )

#define Unmarshal_INT8( sysContext, var ) Unmarshal_int8_t( sysContext, (int8_t *)var )

#define Marshal_BOOL( sysContext, var ) Marshal_int( sysContext, (int *)var )

#define Unmarshal_BOOL( sysContext, var ) Unmarshal_int( sysContext, (int *)var )

#define Marshal_INT16( sysContext, var ) Marshal_int16_t( sysContext, (int16_t *)var )

#define Unmarshal_INT16( sysContext, var ) Unmarshal_int16_t( sysContext, (int16_t *)var )

#define Marshal_INT64( sysContext, var ) Marshal_int64_t( sysContext, (int64_t *)var )

#define Unmarshal_INT64( sysContext, var ) Unmarshal_int64_t( sysContext, (int64_t *)var )

#define Marshal_TPM_ALGORITHM_ID( sysContext, var ) Marshal_UINT32( sysContext, (UINT32 *)var )

#define Unmarshal_TPM_ALGORITHM_ID( sysContext, var ) Unmarshal_UINT32( sysContext, (UINT32 *)var )

#define Marshal_TPM_MODIFIER_INDICATOR( sysContext, var ) Marshal_UINT32( sysContext, (UINT32 *)var )

#define Unmarshal_TPM_MODIFIER_INDICATOR( sysContext, var ) Unmarshal_UINT32( sysContext, (UINT32 *)var )

#define Marshal_TPM_AUTHORIZATION_SIZE( sysContext, var ) Marshal_UINT32( sysContext, (UINT32 *)var )

#define Unmarshal_TPM_AUTHORIZATION_SIZE( sysContext, var ) Unmarshal_UINT32( sysContext, (UINT32 *)var )

#define Marshal_TPM_PARAMETER_SIZE( sysContext, var ) Marshal_UINT32( sysContext, (UINT32 *)var )

#define Unmarshal_TPM_PARAMETER_SIZE( sysContext, var ) Unmarshal_UINT32( sysContext, (UINT32 *)var )

#define Marshal_TPM_KEY_SIZE( sysContext, var ) Marshal_UINT16( sysContext, (UINT16 *)var )

#define Unmarshal_TPM_KEY_SIZE( sysContext, var ) Unmarshal_UINT16( sysContext, (UINT16 *)var )

#define Marshal_TPM_KEY_BITS( sysContext, var ) Marshal_UINT16( sysContext, (UINT16 *)var )

#define Unmarshal_TPM_KEY_BITS( sysContext, var ) Unmarshal_UINT16( sysContext, (UINT16 *)var )

#define Marshal_TPM2B_NONCE( sysContext, var ) Marshal_TPM2B_DIGEST( sysContext, (TPM2B_DIGEST *)var )

#define Unmarshal_TPM2B_NONCE( sysContext, var ) Unmarshal_TPM2B_DIGEST( sysContext, (TPM2B_DIGEST *)var )

#define Marshal_TPM2B_AUTH( sysContext, var ) Marshal_TPM2B_DIGEST( sysContext, (TPM2B_DIGEST *)var )

#define Unmarshal_TPM2B_AUTH( sysContext, var ) Unmarshal_TPM2B_DIGEST( sysContext, (TPM2B_DIGEST *)var )

#define Marshal_TPM2B_OPERAND( sysContext, var ) Marshal_TPM2B_DIGEST( sysContext, (TPM2B_DIGEST *)var )

#define Unmarshal_TPM2B_OPERAND( sysContext, var ) Unmarshal_TPM2B_DIGEST( sysContext, (TPM2B_DIGEST *)var )

#define Marshal_TPM2B_TIMEOUT( sysContext, var ) Marshal_TPM2B_DIGEST( sysContext, (TPM2B_DIGEST *)var )

#define Unmarshal_TPM2B_TIMEOUT( sysContext, var ) Unmarshal_TPM2B_DIGEST( sysContext, (TPM2B_DIGEST *)var )

#define Marshal_TPMS_SCHEME_HMAC( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SCHEME_HMAC( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SIG_SCHEME_RSASSA( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SIG_SCHEME_RSASSA( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SIG_SCHEME_RSAPSS( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SIG_SCHEME_RSAPSS( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SIG_SCHEME_ECDSA( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SIG_SCHEME_ECDSA( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SIG_SCHEME_SM2( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SIG_SCHEME_SM2( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SIG_SCHEME_ECSCHNORR( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SIG_SCHEME_ECSCHNORR( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SIG_SCHEME_ECDAA( sysContext, var ) Marshal_TPMS_SCHEME_ECDAA( sysContext, (TPMS_SCHEME_ECDAA *)var )

#define Unmarshal_TPMS_SIG_SCHEME_ECDAA( sysContext, var ) Unmarshal_TPMS_SCHEME_ECDAA( sysContext, (TPMS_SCHEME_ECDAA *)var )

#define Marshal_TPMS_ENC_SCHEME_OAEP( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_ENC_SCHEME_OAEP( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_ENC_SCHEME_RSAES( sysContext, var ) Marshal_TPMS_EMPTY( sysContext, (TPMS_EMPTY *)var )

#define Unmarshal_TPMS_ENC_SCHEME_RSAES( sysContext, var ) Unmarshal_TPMS_EMPTY( sysContext, (TPMS_EMPTY *)var )

#define Marshal_TPMS_KEY_SCHEME_ECDH( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_KEY_SCHEME_ECDH( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_KEY_SCHEME_ECMQV( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_KEY_SCHEME_ECMQV( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SCHEME_MGF1( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SCHEME_MGF1( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SCHEME_KDF1_SP800_56A( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SCHEME_KDF1_SP800_56A( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SCHEME_KDF2( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SCHEME_KDF2( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SCHEME_KDF1_SP800_108( sysContext, var ) Marshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Unmarshal_TPMS_SCHEME_KDF1_SP800_108( sysContext, var ) Unmarshal_TPMS_SCHEME_HASH( sysContext, (TPMS_SCHEME_HASH *)var )

#define Marshal_TPMS_SIGNATURE_RSASSA( sysContext, var ) Marshal_TPMS_SIGNATURE_RSA( sysContext, (TPMS_SIGNATURE_RSA *)var )

#define Unmarshal_TPMS_SIGNATURE_RSASSA( sysContext, var ) Unmarshal_TPMS_SIGNATURE_RSA( sysContext, (TPMS_SIGNATURE_RSA *)var )

#define Marshal_TPMS_SIGNATURE_RSAPSS( sysContext, var ) Marshal_TPMS_SIGNATURE_RSA( sysContext, (TPMS_SIGNATURE_RSA *)var )

#define Unmarshal_TPMS_SIGNATURE_RSAPSS( sysContext, var ) Unmarshal_TPMS_SIGNATURE_RSA( sysContext, (TPMS_SIGNATURE_RSA *)var )

#define Marshal_TPMS_SIGNATURE_ECDSA( sysContext, var ) Marshal_TPMS_SIGNATURE_ECC( sysContext, (TPMS_SIGNATURE_ECC *)var )

#define Unmarshal_TPMS_SIGNATURE_ECDSA( sysContext, var ) Unmarshal_TPMS_SIGNATURE_ECC( sysContext, (TPMS_SIGNATURE_ECC *)var )

#define Marshal_TPMS_SIGNATURE_ECDAA( sysContext, var ) Marshal_TPMS_SIGNATURE_ECC( sysContext, (TPMS_SIGNATURE_ECC *)var )

#define Unmarshal_TPMS_SIGNATURE_ECDAA( sysContext, var ) Unmarshal_TPMS_SIGNATURE_ECC( sysContext, (TPMS_SIGNATURE_ECC *)var )

#define Marshal_TPMS_SIGNATURE_SM2( sysContext, var ) Marshal_TPMS_SIGNATURE_ECC( sysContext, (TPMS_SIGNATURE_ECC *)var )

#define Unmarshal_TPMS_SIGNATURE_SM2( sysContext, var ) Unmarshal_TPMS_SIGNATURE_ECC( sysContext, (TPMS_SIGNATURE_ECC *)var )

#define Marshal_TPMS_SIGNATURE_ECSCHNORR( sysContext, var ) Marshal_TPMS_SIGNATURE_ECC( sysContext, (TPMS_SIGNATURE_ECC *)var )

#define Unmarshal_TPMS_SIGNATURE_ECSCHNORR( sysContext, var ) Unmarshal_TPMS_SIGNATURE_ECC( sysContext, (TPMS_SIGNATURE_ECC *)var )

void Marshal_TPML_ALG(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_ALG *alg
	);

void Marshal_TPMT_SYM_DEF(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SYM_DEF *symDef
	);

void Marshal_TPM2B_SENSITIVE_CREATE(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_SENSITIVE_CREATE *sensitiveCreate
	);

void Marshal_TPM2B_PUBLIC(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_PUBLIC *publicVar
	);

void Marshal_TPML_PCR_SELECTION(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_PCR_SELECTION *pcrSelection
	);

void Marshal_TPM2B_SENSITIVE(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_SENSITIVE *sensitive
	);

void Marshal_TPMT_SYM_DEF_OBJECT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SYM_DEF_OBJECT *symDefObject
	);

void Marshal_TPMT_RSA_DECRYPT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_RSA_DECRYPT *rsaDecrypt
	);

void Marshal_TPM2B_ECC_POINT(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_ECC_POINT *eccPoint
	);

void Marshal_TPMT_SIG_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SIG_SCHEME *sigScheme
	);

void Marshal_TPMT_TK_CREATION(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_TK_CREATION *tkCreation
	);

void Marshal_TPMT_SIGNATURE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SIGNATURE *signature
	);

void Marshal_TPMT_TK_HASHCHECK(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_TK_HASHCHECK *tkHashcheck
	);

void Marshal_TPML_CC(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_CC *cc
	);

void Marshal_TPML_DIGEST_VALUES(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_DIGEST_VALUES *digestValues
	);

void Marshal_TPMT_TK_AUTH(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_TK_AUTH *tkAuth
	);

void Marshal_TPML_DIGEST(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_DIGEST *digest
	);

void Marshal_TPMA_LOCALITY(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_LOCALITY locality
	);

void Marshal_TPMT_TK_VERIFIED(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_TK_VERIFIED *tkVerified
	);

void Marshal_TPMS_CONTEXT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CONTEXT *context
	);

void Marshal_TPMT_PUBLIC_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_PUBLIC_PARMS *publicVarParms
	);

void Marshal_TPM2B_NV_PUBLIC(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_NV_PUBLIC *nvPublic
	);

void Marshal_TPMA_ALGORITHM(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_ALGORITHM algorithm
	);

void Marshal_TPMA_OBJECT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_OBJECT object
	);

void Marshal_TPMA_SESSION(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_SESSION session
	);

void Marshal_TPMU_HA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_HA *ha,
	UINT32 selector
	);

void Marshal_TPMT_HA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_HA *ha
	);

void Marshal_TPMS_PCR_SELECT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_PCR_SELECT *pcrSelect
	);

void Marshal_TPMS_PCR_SELECTION(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_PCR_SELECTION *pcrSelection
	);

void Marshal_TPMS_CLOCK_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CLOCK_INFO *clockInfo
	);

void Marshal_TPMS_TIME_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_TIME_INFO *timeInfo
	);

void Marshal_TPMS_AUTH_COMMAND(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_AUTH_COMMAND *authCommand
	);

void Marshal_TPMU_SYM_KEY_BITS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SYM_KEY_BITS *symKeyBits,
	UINT32 selector
	);

void Marshal_TPMU_SYM_MODE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SYM_MODE *symMode,
	UINT32 selector
	);

void Marshal_TPMS_SYMCIPHER_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SYMCIPHER_PARMS *symcipherParms
	);

void Marshal_TPMS_SENSITIVE_CREATE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SENSITIVE_CREATE *sensitiveCreate
	);

void Marshal_TPMS_SCHEME_HASH(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SCHEME_HASH *schemeHash
	);

void Marshal_TPMS_SCHEME_ECDAA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SCHEME_ECDAA *schemeEcdaa
	);

void Marshal_TPMS_SCHEME_XOR(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SCHEME_XOR *schemeXor
	);

void Marshal_TPMU_SCHEME_KEYEDHASH(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SCHEME_KEYEDHASH *schemeKeyedhash,
	UINT32 selector
	);

void Marshal_TPMT_KEYEDHASH_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_KEYEDHASH_SCHEME *keyedhashScheme
	);

void Marshal_TPMU_SIG_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SIG_SCHEME *sigScheme,
	UINT32 selector
	);

void Marshal_TPMU_KDF_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_KDF_SCHEME *kdfScheme,
	UINT32 selector
	);

void Marshal_TPMT_KDF_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_KDF_SCHEME *kdfScheme
	);

void Marshal_TPMU_ASYM_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_ASYM_SCHEME *asymScheme,
	UINT32 selector
	);

void Marshal_TPMT_RSA_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_RSA_SCHEME *rsaScheme
	);

void Marshal_TPMS_ECC_POINT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ECC_POINT *eccPoint
	);

void Marshal_TPMT_ECC_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_ECC_SCHEME *eccScheme
	);

void Marshal_TPMS_SIGNATURE_RSA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SIGNATURE_RSA *signatureRsa
	);

void Marshal_TPMS_SIGNATURE_ECC(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SIGNATURE_ECC *signatureEcc
	);

void Marshal_TPMU_SIGNATURE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SIGNATURE *signature,
	UINT32 selector
	);

void Marshal_TPMU_PUBLIC_ID(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_PUBLIC_ID *publicVarId,
	UINT32 selector
	);

void Marshal_TPMS_KEYEDHASH_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_KEYEDHASH_PARMS *keyedhashParms
	);

void Marshal_TPMS_RSA_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_RSA_PARMS *rsaParms
	);

void Marshal_TPMS_ECC_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ECC_PARMS *eccParms
	);

void Marshal_TPMU_PUBLIC_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_PUBLIC_PARMS *publicVarParms,
	UINT32 selector
	);

void Marshal_TPMT_PUBLIC(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_PUBLIC *publicVar
	);

void Marshal_TPMU_SENSITIVE_COMPOSITE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SENSITIVE_COMPOSITE *sensitiveComposite,
	UINT32 selector
	);

void Marshal_TPMT_SENSITIVE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SENSITIVE *sensitive
	);

void Marshal_TPMS_NV_PIN_COUNTER_PARAMETERS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_NV_PIN_COUNTER_PARAMETERS *nvPinCounterParameters
	);

void Marshal_TPMA_NV(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_NV nv
	);

void Marshal_TPMS_NV_PUBLIC(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_NV_PUBLIC *nvPublic
	);

void Marshal_TPMS_CONTEXT_DATA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CONTEXT_DATA *contextData
	);

void Unmarshal_TPML_ALG(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_ALG *alg
	);

void Unmarshal_TPM2B_PUBLIC(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_PUBLIC *publicVar
	);

void Unmarshal_TPM2B_CREATION_DATA(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_CREATION_DATA *creationData
	);

void Unmarshal_TPMT_TK_CREATION(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_TK_CREATION *tkCreation
	);

void Unmarshal_TPM2B_ECC_POINT(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_ECC_POINT *eccPoint
	);

void Unmarshal_TPMS_ALGORITHM_DETAIL_ECC(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ALGORITHM_DETAIL_ECC *algorithmDetailEcc
	);

void Unmarshal_TPMT_TK_HASHCHECK(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_TK_HASHCHECK *tkHashcheck
	);

void Unmarshal_TPML_DIGEST_VALUES(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_DIGEST_VALUES *digestValues
	);

void Unmarshal_TPMT_SIGNATURE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SIGNATURE *signature
	);

void Unmarshal_TPMT_TK_VERIFIED(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_TK_VERIFIED *tkVerified
	);

void Unmarshal_TPML_PCR_SELECTION(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_PCR_SELECTION *pcrSelection
	);

void Unmarshal_TPML_DIGEST(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_DIGEST *digest
	);

void Unmarshal_TPMT_TK_AUTH(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_TK_AUTH *tkAuth
	);

void Unmarshal_TPMT_HA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_HA *ha
	);

void Unmarshal_TPMS_CONTEXT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CONTEXT *context
	);

void Unmarshal_TPMS_TIME_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_TIME_INFO *timeInfo
	);

void Unmarshal_TPMS_CAPABILITY_DATA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CAPABILITY_DATA *capabilityData
	);

void Unmarshal_TPM2B_NV_PUBLIC(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_NV_PUBLIC *nvPublic
	);

void Unmarshal_TPMA_ALGORITHM(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_ALGORITHM *algorithm
	);

void Unmarshal_TPMA_OBJECT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_OBJECT *object
	);

void Unmarshal_TPMA_SESSION(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_SESSION *session
	);

void Unmarshal_TPMA_LOCALITY(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_LOCALITY *locality
	);

void Unmarshal_TPMA_PERMANENT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_PERMANENT *permanent
	);

void Unmarshal_TPMA_STARTUP_CLEAR(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_STARTUP_CLEAR *startupClear
	);

void Unmarshal_TPMA_CC(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_CC *cc
	);

void Unmarshal_TPMS_ALGORITHM_DESCRIPTION(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ALGORITHM_DESCRIPTION *algorithmDescription
	);

void Unmarshal_TPMU_HA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_HA *ha,
	UINT32 selector
	);

void Unmarshal_TPMS_PCR_SELECT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_PCR_SELECT *pcrSelect
	);

void Unmarshal_TPMS_PCR_SELECTION(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_PCR_SELECTION *pcrSelection
	);

void Unmarshal_TPMS_ALG_PROPERTY(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ALG_PROPERTY *algProperty
	);

void Unmarshal_TPMS_TAGGED_PROPERTY(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_TAGGED_PROPERTY *taggedProperty
	);

void Unmarshal_TPMS_TAGGED_PCR_SELECT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_TAGGED_PCR_SELECT *taggedPcrSelect
	);

void Unmarshal_TPML_CC(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_CC *cc
	);

void Unmarshal_TPML_CCA(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_CCA *cca
	);

void Unmarshal_TPML_HANDLE(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_HANDLE *handle
	);

void Unmarshal_TPML_ALG_PROPERTY(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_ALG_PROPERTY *algProperty
	);

void Unmarshal_TPML_TAGGED_TPM_PROPERTY(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_TAGGED_TPM_PROPERTY *taggedTpmProperty
	);

void Unmarshal_TPML_INTEL_PTT_PROPERTY(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_INTEL_PTT_PROPERTY *intelPttProperty
);

void Unmarshal_TPML_TAGGED_PCR_PROPERTY(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_TAGGED_PCR_PROPERTY *taggedPcrProperty
	);

void Unmarshal_TPML_ECC_CURVE(
	TSS2_SYS_CONTEXT *sysContext,
	TPML_ECC_CURVE *eccCurve
	);

void Unmarshal_TPMU_CAPABILITIES(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_CAPABILITIES *capabilities,
	UINT32 selector
	);

void Unmarshal_TPMS_CLOCK_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CLOCK_INFO *clockInfo
	);

void Unmarshal_TPMS_TIME_ATTEST_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_TIME_ATTEST_INFO *timeAttestInfo
	);

void Unmarshal_TPMS_CERTIFY_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CERTIFY_INFO *certifyInfo
	);

void Unmarshal_TPMS_QUOTE_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_QUOTE_INFO *quoteInfo
	);

void Unmarshal_TPMS_COMMAND_AUDIT_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_COMMAND_AUDIT_INFO *commandAuditInfo
	);

void Unmarshal_TPMS_SESSION_AUDIT_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SESSION_AUDIT_INFO *sessionAuditInfo
	);

void Unmarshal_TPMS_CREATION_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CREATION_INFO *creationInfo
	);

void Unmarshal_TPMS_NV_CERTIFY_INFO(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_NV_CERTIFY_INFO *nvCertifyInfo
	);

void Unmarshal_TPMU_ATTEST(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_ATTEST *attest,
	UINT32 selector
	);

void Unmarshal_TPMS_ATTEST(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ATTEST *attest
	);

void Unmarshal_TPMS_AUTH_RESPONSE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_AUTH_RESPONSE *authResponse
	);

void Unmarshal_TPMU_SYM_KEY_BITS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SYM_KEY_BITS *symKeyBits,
	UINT32 selector
	);

void Unmarshal_TPMU_SYM_MODE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SYM_MODE *symMode,
	UINT32 selector
	);

void Unmarshal_TPMT_SYM_DEF(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SYM_DEF *symDef
	);

void Unmarshal_TPMT_SYM_DEF_OBJECT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SYM_DEF_OBJECT *symDefObject
	);

void Unmarshal_TPMS_SYMCIPHER_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SYMCIPHER_PARMS *symcipherParms
	);

void Unmarshal_TPMS_SCHEME_HASH(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SCHEME_HASH *schemeHash
	);

void Unmarshal_TPMS_SCHEME_ECDAA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SCHEME_ECDAA *schemeEcdaa
	);

void Unmarshal_TPMS_SCHEME_XOR(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SCHEME_XOR *schemeXor
	);

void Unmarshal_TPMU_SCHEME_KEYEDHASH(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SCHEME_KEYEDHASH *schemeKeyedhash,
	UINT32 selector
	);

void Unmarshal_TPMT_KEYEDHASH_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_KEYEDHASH_SCHEME *keyedhashScheme
	);

void Unmarshal_TPMU_SIG_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SIG_SCHEME *sigScheme,
	UINT32 selector
	);

void Unmarshal_TPMT_SIG_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SIG_SCHEME *sigScheme
	);

void Unmarshal_TPMU_KDF_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_KDF_SCHEME *kdfScheme,
	UINT32 selector
	);

void Unmarshal_TPMT_KDF_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_KDF_SCHEME *kdfScheme
	);

void Unmarshal_TPMU_ASYM_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_ASYM_SCHEME *asymScheme,
	UINT32 selector
	);

void Unmarshal_TPMT_RSA_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_RSA_SCHEME *rsaScheme
	);

void Unmarshal_TPMT_RSA_DECRYPT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_RSA_DECRYPT *rsaDecrypt
	);

void Unmarshal_TPMS_ECC_POINT(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ECC_POINT *eccPoint
	);

void Unmarshal_TPMT_ECC_SCHEME(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_ECC_SCHEME *eccScheme
	);

void Unmarshal_TPMS_SIGNATURE_RSA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SIGNATURE_RSA *signatureRsa
	);

void Unmarshal_TPMS_SIGNATURE_ECC(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_SIGNATURE_ECC *signatureEcc
	);

void Unmarshal_TPMU_SIGNATURE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SIGNATURE *signature,
	UINT32 selector
	);

void Unmarshal_TPMU_PUBLIC_ID(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_PUBLIC_ID *publicVarId,
	UINT32 selector
	);

void Unmarshal_TPMS_KEYEDHASH_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_KEYEDHASH_PARMS *keyedhashParms
	);

void Unmarshal_TPMS_RSA_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_RSA_PARMS *rsaParms
	);

void Unmarshal_TPMS_ECC_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_ECC_PARMS *eccParms
	);

void Unmarshal_TPMU_PUBLIC_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_PUBLIC_PARMS *publicVarParms,
	UINT32 selector
	);

void Unmarshal_TPMT_PUBLIC_PARMS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_PUBLIC_PARMS *publicVarParms
	);

void Unmarshal_TPMT_PUBLIC(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_PUBLIC *publicVar
	);

void Unmarshal_TPMU_SENSITIVE_COMPOSITE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMU_SENSITIVE_COMPOSITE *sensitiveComposite,
	UINT32 selector
	);

void Unmarshal_TPMT_SENSITIVE(
	TSS2_SYS_CONTEXT *sysContext,
	TPMT_SENSITIVE *sensitive
	);

void Unmarshal_TPM2B_SENSITIVE(
	TSS2_SYS_CONTEXT *sysContext,
	TPM2B_SENSITIVE *sensitive
	);

void Unmarshal_TPMS_NV_PIN_COUNTER_PARAMETERS(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_NV_PIN_COUNTER_PARAMETERS *nvPinCounterParameters
	);

void Unmarshal_TPMA_NV(
	TSS2_SYS_CONTEXT *sysContext,
	TPMA_NV *nv
	);

void Unmarshal_TPMS_NV_PUBLIC(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_NV_PUBLIC *nvPublic
	);

void Unmarshal_TPMS_CONTEXT_DATA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CONTEXT_DATA *contextData
	);

void Unmarshal_TPMS_CREATION_DATA(
	TSS2_SYS_CONTEXT *sysContext,
	TPMS_CREATION_DATA *creationData
	);


#endif
