#;**********************************************************************;
#
# Copyright (c) 2015, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, 
# this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation 
# and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

bin_PROGRAMS = resourcemgr/resourcemgr test/tpmclient/tpmclient
noinst_LIBRARIES = sysapi/libtpm.a

resourcemgr_resourcemgr_CFLAGS   = $(RESOURCEMGR_INC)
resourcemgr_resourcemgr_CXXFLAGS = $(RESOURCEMGR_INC)
resourcemgr_resourcemgr_LDADD    = $(noinst_LIBRARIES)
resourcemgr_resourcemgr_LDFLAGS  = -lpthread
resourcemgr_resourcemgr_SOURCES  = $(RESOURCEMGR_SRC) $(TPMSOCKETS_SRC) \
     $(LOCALTPM_SRC) $(COMMON_SRC)

sysapi_libtpm_a_CFLAGS  = -I$(srcdir)/sysapi/include/
sysapi_libtpm_a_SOURCES = $(SYSAPI_SRC) $(SYSAPIUTIL_SRC) $(SYSAPI_INC)

test_tpmclient_tpmclient_CFLAGS   = -DSAPI_CLIENT $(TPMCLIENT_INC)
test_tpmclient_tpmclient_CXXFLAGS = -DSAPI_CLIENT $(TPMCLIENT_INC)
test_tpmclient_tpmclient_LDADD    = $(noinst_LIBRARIES)
test_tpmclient_tpmclient_SOURCES  = $(COMMON_SRC) $(SAMPLE_SRC) \
    $(TPMCLIENT_SRC) $(TPMSOCKETS_SRC)

COMMON_SRC = \
    common/debug.c common/debug.h \
    common/getcommands.c \
    common/platformcommand.c common/platform.h \
    common/syscontext.c common/syscontext.h

LOCALTPM_SRC = tcti/localtpm/localtpm.c tcti/localtpm/localtpm.h
RESOURCEMGR_INC = -I$(srcdir)/sysapi/include -I$(srcdir)/common \
    -I$(srcdir)/tcti/tpmsockets -I$(srcdir)/tcti/localtpm \
    -I$(srcdir)/resourcemgr -I$(srcdir)/test/tpmclient
RESOURCEMGR_SRC = resourcemgr/resourcemgr.c resourcemgr/resourcemgr.h
TPMSOCKETS_SRC = tcti/tpmsockets/tpmsockets.cpp \
    tcti/tpmsockets/tpmsockets.h

TPMCLIENT_INC = -I$(srcdir)/sysapi/include -I$(srcdir)/test/tpmclient \
    -I$(srcdir)/tcti/tpmsockets -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMCLIENT_SRC = test/tpmclient/tpmclient.cpp test/tpmclient/tpmclient.h
SAMPLE_SRC = \
    test/common/sample/CatSizedByteBuffer.c \
    test/common/sample/CopySizedBuffer.c \
    test/common/sample/CreateNullSession.c \
    test/common/sample/DecryptEncrypt.c \
    test/common/sample/Entity.c \
    test/common/sample/kdfa.c \
    test/common/sample/LoadExternalHMACKey.c \
    test/common/sample/sample.h \
    test/common/sample/SessionHmac.c \
    test/common/sample/SetLocality.c \
    test/common/sample/StartAuthSession.c \
    test/common/sample/TpmCalcPHash.c \
    test/common/sample/TpmHandleToName.c \
    test/common/sample/TpmHash.c \
    test/common/sample/TpmHmac.c \
    test/common/sample/sample.h

SYSAPI_SRC = \
    sysapi/sysapi/Tss2_Sys_ECC_Parameters.c \
    sysapi/sysapi/Tss2_Sys_NV_Write.c \
    sysapi/sysapi/Tss2_Sys_ECDH_ZGen.c \
    sysapi/sysapi/Tss2_Sys_HMAC_Start.c \
    sysapi/sysapi/Tss2_Sys_FieldUpgradeStart.c \
    sysapi/sysapi/Tss2_Sys_ObjectChangeAuth.c \
    sysapi/sysapi/Tss2_Sys_Vendor_TCG_Test.c \
    sysapi/sysapi/Tss2_Sys_Unseal.c \
    sysapi/sysapi/Tss2_Sys_NV_ChangeAuth.c \
    sysapi/sysapi/Tss2_Sys_Shutdown.c \
    sysapi/sysapi/Tss2_Sys_PolicyAuthValue.c \
    sysapi/sysapi/Tss2_Sys_PolicyNVWritten.c \
    sysapi/sysapi/GetCommandCode.c \
    sysapi/sysapi/Tss2_Sys_DictionaryAttackLockReset.c \
    sysapi/sysapi/Tss2_Sys_StartAuthSession.c \
    sysapi/sysapi/Tss2_Sys_Certify.c \
    sysapi/sysapi/Tss2_Sys_PolicyDuplicationSelect.c \
    sysapi/sysapi/Tss2_Sys_NV_WriteLock.c \
    sysapi/sysapi/Tss2_Sys_PolicyCounterTimer.c \
    sysapi/sysapi/Tss2_Sys_PCR_SetAuthValue.c \
    sysapi/sysapi/Tss2_Sys_DictionaryAttackParameters.c \
    sysapi/sysapi/Tss2_Sys_PolicyPhysicalPresence.c \
    sysapi/sysapi/Tss2_Sys_Create.c \
    sysapi/sysapi/Tss2_Sys_ContextSave.c \
    sysapi/sysapi/Tss2_Sys_PolicyCommandCode.c \
    sysapi/sysapi/Tss2_Sys_NV_Extend.c \
    sysapi/sysapi/Tss2_Sys_RSA_Encrypt.c \
    sysapi/sysapi/Tss2_Sys_ActivateCredential.c \
    sysapi/sysapi/Tss2_Sys_PolicySigned.c \
    sysapi/sysapi/Tss2_Sys_SelfTest.c \
    sysapi/sysapi/Tss2_Sys_HierarchyChangeAuth.c \
    sysapi/sysapi/Tss2_Sys_PCR_Read.c \
    sysapi/sysapi/Tss2_Sys_PolicyGetDigest.c \
    sysapi/sysapi/Tss2_Sys_ECDH_KeyGen.c \
    sysapi/sysapi/Tss2_Sys_PCR_Allocate.c \
    sysapi/sysapi/Tss2_Sys_NV_UndefineSpace.c \
    sysapi/sysapi/Tss2_Sys_HMAC.c \
    sysapi/sysapi/Tss2_Sys_Rewrap.c \
    sysapi/sysapi/Tss2_Sys_Commit.c \
    sysapi/sysapi/EncryptParam.c \
    sysapi/sysapi/Tss2_Sys_FieldUpgradeData.c \
    sysapi/sysapi/Tss2_Sys_NV_Increment.c \
    sysapi/sysapi/Tss2_Sys_GetCapability.c \
    sysapi/sysapi/Tss2_Sys_PolicyLocality.c \
    sysapi/sysapi/Tss2_Sys_NV_SetBits.c \
    sysapi/sysapi/execute.c \
    sysapi/sysapi/Tss2_Sys_SequenceUpdate.c \
    sysapi/sysapi/Tss2_Sys_VerifySignature.c \
    sysapi/sysapi/Tss2_Sys_NV_DefineSpace.c \
    sysapi/sysapi/Tss2_Sys_PolicyNV.c \
    sysapi/sysapi/Tss2_Sys_Quote.c \
    sysapi/sysapi/Tss2_Sys_NV_Certify.c \
    sysapi/sysapi/Tss2_Sys_PolicyAuthorize.c \
    sysapi/sysapi/Tss2_Sys_PolicyCpHash.c \
    sysapi/sysapi/Tss2_Sys_GetRandom.c \
    sysapi/sysapi/Tss2_Sys_RSA_Decrypt.c \
    sysapi/sysapi/Tss2_Sys_NV_ReadLock.c \
    sysapi/sysapi/Tss2_Sys_PolicyTicket.c \
    sysapi/sysapi/Tss2_Sys_Hash.c \
    sysapi/sysapi/Tss2_Sys_NV_GlobalWriteLock.c \
    sysapi/sysapi/Tss2_Sys_Load.c \
    sysapi/sysapi/Tss2_Sys_Import.c \
    sysapi/sysapi/Tss2_Sys_FirmwareRead.c \
    sysapi/sysapi/GetTctiContext.c \
    sysapi/sysapi/Tss2_Sys_FlushContext.c \
    sysapi/sysapi/Tss2_Sys_PP_Commands.c \
    sysapi/sysapi/Tss2_Sys_IncrementalSelfTest.c \
    sysapi/sysapi/authorizations.c \
    sysapi/sysapi/Tss2_Sys_PCR_Event.c \
    sysapi/sysapi/Tss2_Sys_LoadExternal.c \
    sysapi/sysapi/Tss2_Sys_CertifyCreation.c \
    sysapi/sysapi/Tss2_Sys_SetAlgorithmSet.c \
    sysapi/sysapi/Tss2_Sys_SequenceComplete.c \
    sysapi/sysapi/Tss2_Sys_PCR_SetAuthPolicy.c \
    sysapi/sysapi/Tss2_Sys_GetTestResult.c \
    sysapi/sysapi/Tss2_Sys_ClearControl.c \
    sysapi/sysapi/Tss2_Sys_PolicyNameHash.c \
    sysapi/sysapi/Tss2_Sys_PCR_Extend.c \
    sysapi/sysapi/Tss2_Sys_GetTime.c \
    sysapi/sysapi/Tss2_Sys_PolicyRestart.c \
    sysapi/sysapi/Tss2_Sys_PolicyPCR.c \
    sysapi/sysapi/Tss2_Sys_HierarchyControl.c \
    sysapi/sysapi/Tss2_Sys_TestParms.c \
    sysapi/sysapi/Tss2_Sys_NV_Read.c \
    sysapi/sysapi/Tss2_Sys_EvictControl.c \
    sysapi/sysapi/Tss2_Sys_ReadClock.c \
    sysapi/sysapi/GetRpBuffer.c \
    sysapi/sysapi/DecryptParam.c \
    sysapi/sysapi/Tss2_Sys_EC_Ephemeral.c \
    sysapi/sysapi/Tss2_Sys_PolicyOR.c \
    sysapi/sysapi/Tss2_Sys_NV_ReadPublic.c \
    sysapi/sysapi/Tss2_Sys_Startup.c \
    sysapi/sysapi/Tss2_Sys_CreatePrimary.c \
    sysapi/sysapi/Tss2_Sys_Clear.c \
    sysapi/sysapi/Tss2_Sys_ClockRateAdjust.c \
    sysapi/sysapi/Tss2_Sys_GetSessionAuditDigest.c \
    sysapi/sysapi/Tss2_Sys_Sign.c \
    sysapi/sysapi/Tss2_Sys_ReadPublic.c \
    sysapi/sysapi/Tss2_Sys_NV_UndefineSpaceSpecial.c \
    sysapi/sysapi/Tss2_Sys_GetCommandAuditDigest.c \
    sysapi/sysapi/Tss2_Sys_PolicyPassword.c \
    sysapi/sysapi/Tss2_Sys_PolicySecret.c \
    sysapi/sysapi/Tss2_Sys_SetPrimaryPolicy.c \
    sysapi/sysapi/Tss2_Sys_SetCommandCodeAuditStatus.c \
    sysapi/sysapi/ContextManagement.c \
    sysapi/sysapi/Tss2_Sys_ChangePPS.c \
    sysapi/sysapi/Tss2_Sys_EncryptDecrypt.c \
    sysapi/sysapi/Finalize.c \
    sysapi/sysapi/Tss2_Sys_ClockSet.c \
    sysapi/sysapi/Tss2_Sys_ChangeEPS.c \
    sysapi/sysapi/Tss2_Sys_EventSequenceComplete.c \
    sysapi/sysapi/Tss2_Sys_HashSequenceStart.c \
    sysapi/sysapi/Tss2_Sys_MakeCredential.c \
    sysapi/sysapi/Tss2_Sys_ContextLoad.c \
    sysapi/sysapi/GetCpBuffer.c \
    sysapi/sysapi/Tss2_Sys_StirRandom.c \
    sysapi/sysapi/Tss2_Sys_ZGen_2Phase.c \
    sysapi/sysapi/Tss2_Sys_Duplicate.c \
    sysapi/sysapi/Tss2_Sys_PCR_Reset.c

SYSAPIUTIL_SRC = \
    sysapi/sysapi_util/Unmarshal_TPMS_SESSION_AUDIT_INFO.c \
    sysapi/sysapi_util/Unmarshal_TPM2B_NV_PUBLIC.c \
    sysapi/sysapi_util/Marshal_TPM2B_NV_PUBLIC.c \
    sysapi/sysapi_util/marshal_uint8.c \
    sysapi/sysapi_util/Unmarshal_TPMS_CONTEXT.c \
    sysapi/sysapi_util/Unmarshal_TPMT_PUBLIC.c \
    sysapi/sysapi_util/Unmarshal_TPMS_CAPABILITY_DATA.c \
    sysapi/sysapi_util/Marshal_TPMS_CLOCK_INFO.c \
    sysapi/sysapi_util/Unmarshal_TPML_DIGEST.c \
    sysapi/sysapi_util/Marshal_TPML_DIGEST_VALUES.c \
    sysapi/sysapi_util/unmarshal_uint8.c \
    sysapi/sysapi_util/Marshal_TPMT_RSA_DECRYPT.c \
    sysapi/sysapi_util/Unmarshal_TPMS_ECC_PARMS.c \
    sysapi/sysapi_util/Unmarshal_TPMS_PCR_SELECT.c \
    sysapi/sysapi_util/GetNumHandles.c \
    sysapi/sysapi_util/Marshal_TPMU_KDF_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPML_ALG.c \
    sysapi/sysapi_util/Unmarshal_TPML_PCR_SELECTION.c \
    sysapi/sysapi_util/Marshal_TPMT_TK_AUTH.c \
    sysapi/sysapi_util/Unmarshal_TPMA_ALGORITHM.c \
    sysapi/sysapi_util/Marshal_TPMS_CONTEXT_DATA.c \
    sysapi/sysapi_util/Marshal_TPMT_PUBLIC.c \
    sysapi/sysapi_util/Unmarshal_TPMU_HA.c \
    sysapi/sysapi_util/changeEndian.c \
    sysapi/sysapi_util/Marshal_TPMS_ECC_PARMS.c \
    sysapi/sysapi_util/Marshal_TPMS_SIGNATURE_ECC.c \
    sysapi/sysapi_util/Unmarshal_TPMT_SYM_DEF.c \
    sysapi/sysapi_util/Marshal_TPMU_PUBLIC_PARMS.c \
    sysapi/sysapi_util/Unmarshal_TPM2B_PUBLIC.c \
    sysapi/sysapi_util/Unmarshal_TPMT_KEYEDHASH_SCHEME.c \
    sysapi/sysapi_util/marshal_simple_tpm2b.c \
    sysapi/sysapi_util/Marshal_TPMS_TIME_INFO.c \
    sysapi/sysapi_util/Marshal_TPMS_SENSITIVE_CREATE.c \
    sysapi/sysapi_util/Marshal_TPML_ALG.c \
    sysapi/sysapi_util/Unmarshal_TPMS_KEYEDHASH_PARMS.c \
    sysapi/sysapi_util/Unmarshal_TPMU_SCHEME_KEYEDHASH.c \
    sysapi/sysapi_util/Unmarshal_TPMU_SIG_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPMS_EMPTY.c \
    sysapi/sysapi_util/Marshal_TPMU_HA.c \
    sysapi/sysapi_util/Unmarshal_TPM2B_ECC_POINT.c \
    sysapi/sysapi_util/Marshal_TPMU_SIGNATURE.c \
    sysapi/sysapi_util/Marshal_TPMT_SIGNATURE.c \
    sysapi/sysapi_util/Unmarshal_TPML_HANDLE.c \
    sysapi/sysapi_util/Unmarshal_TPMA_LOCALITY.c \
    sysapi/sysapi_util/Unmarshal_TPMU_SYM_MODE.c \
    sysapi/sysapi_util/Unmarshal_TPMS_SCHEME_ECDAA.c \
    sysapi/sysapi_util/Unmarshal_TPML_CCA.c \
    sysapi/sysapi_util/Marshal_TPMT_TK_CREATION.c \
    sysapi/sysapi_util/Unmarshal_TPMS_ALG_PROPERTY.c \
    sysapi/sysapi_util/Unmarshal_TPMS_CREATION_DATA.c \
    sysapi/sysapi_util/Unmarshal_TPMA_CC.c \
    sysapi/sysapi_util/CompareSizedByteBuffer.c \
    sysapi/sysapi_util/Unmarshal_TPMA_SESSION.c \
    sysapi/sysapi_util/Unmarshal_TPMS_CREATION_INFO.c \
    sysapi/sysapi_util/Unmarshal_TPMT_KDF_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPMU_ATTEST.c \
    sysapi/sysapi_util/Marshal_TPMS_PCR_SELECTION.c \
    sysapi/sysapi_util/Unmarshal_TPMA_PERMANENT.c \
    sysapi/sysapi_util/Unmarshal_TPMS_SCHEME_HASH.c \
    sysapi/sysapi_util/Unmarshal_TPMT_TK_CREATION.c \
    sysapi/sysapi_util/Marshal_TPMT_HA.c \
    sysapi/sysapi_util/Marshal_TPMT_SYM_DEF_OBJECT.c \
    sysapi/sysapi_util/Marshal_TPML_PCR_SELECTION.c \
    sysapi/sysapi_util/Marshal_TPMT_KEYEDHASH_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPMA_STARTUP_CLEAR.c \
    sysapi/sysapi_util/Unmarshal_TPMU_ASYM_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPML_ALG_PROPERTY.c \
    sysapi/sysapi_util/Unmarshal_TPMT_RSA_DECRYPT.c \
    sysapi/sysapi_util/Marshal_TPML_CC.c \
    sysapi/sysapi_util/Unmarshal_TPMS_PCR_SELECTION.c \
    sysapi/sysapi_util/Marshal_TPMS_KEYEDHASH_PARMS.c \
    sysapi/sysapi_util/Unmarshal_TPMU_SYM_KEY_BITS.c \
    sysapi/sysapi_util/Unmarshal_TPMS_SIGNATURE_RSA.c \
    sysapi/sysapi_util/Marshal_TPM2B_PUBLIC.c \
    sysapi/sysapi_util/Marshal_TPMS_SCHEME_ECDAA.c \
    sysapi/sysapi_util/GetDigestSize.c \
    sysapi/sysapi_util/Unmarshal_TPML_DIGEST_VALUES.c \
    sysapi/sysapi_util/Marshal_TPMT_RSA_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPMS_ALGORITHM_DETAIL_ECC.c \
    sysapi/sysapi_util/Unmarshal_TPMS_QUOTE_INFO.c \
    sysapi/sysapi_util/Marshal_TPMS_EMPTY.c \
    sysapi/sysapi_util/Unmarshal_TPMU_SENSITIVE_COMPOSITE.c \
    sysapi/sysapi_util/Unmarshal_TPMS_TAGGED_PCR_SELECT.c \
    sysapi/sysapi_util/Unmarshal_TPMT_ECC_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPMS_SCHEME_XOR.c \
    sysapi/sysapi_util/Marshal_TPM2B_SENSITIVE.c \
    sysapi/sysapi_util/Unmarshal_TPMS_ALGORITHM_DESCRIPTION.c \
    sysapi/sysapi_util/checkoverflow.c \
    sysapi/sysapi_util/Marshal_TPMT_SIG_SCHEME.c \
    sysapi/sysapi_util/Marshal_TPMU_ASYM_SCHEME.c \
    sysapi/sysapi_util/Marshal_TPMU_SENSITIVE_COMPOSITE.c \
    sysapi/sysapi_util/Unmarshal_TPMT_HA.c \
    sysapi/sysapi_util/Marshal_TPMS_SCHEME_HASH.c \
    sysapi/sysapi_util/Marshal_TPMU_PUBLIC_ID.c \
    sysapi/sysapi_util/Marshal_TPMT_TK_VERIFIED.c \
    sysapi/sysapi_util/CopySessionData.c \
    sysapi/sysapi_util/Marshal_TPMS_PCR_SELECT.c \
    sysapi/sysapi_util/CommandUtil.c \
    sysapi/sysapi_util/Unmarshal_TPMS_SYMCIPHER_PARMS.c \
    sysapi/sysapi_util/Unmarshal_TPMT_SYM_DEF_OBJECT.c \
    sysapi/sysapi_util/Unmarshal_TPM2B_SENSITIVE.c \
    sysapi/sysapi_util/Unmarshal_TPMS_COMMAND_AUDIT_INFO.c \
    sysapi/sysapi_util/marshal_uint16.c \
    sysapi/sysapi_util/Marshal_TPMU_SCHEME_KEYEDHASH.c \
    sysapi/sysapi_util/Unmarshal_TPMT_TK_VERIFIED.c \
    sysapi/sysapi_util/unmarshal_uint32.c \
    sysapi/sysapi_util/Unmarshal_TPMS_AUTH_RESPONSE.c \
    sysapi/sysapi_util/Marshal_TPMS_RSA_PARMS.c \
    sysapi/sysapi_util/Marshal_TPMS_SCHEME_XOR.c \
    sysapi/sysapi_util/Unmarshal_TPMS_NV_CERTIFY_INFO.c \
    sysapi/sysapi_util/Unmarshal_TPMT_TK_HASHCHECK.c \
    sysapi/sysapi_util/Marshal_TPMU_SYM_KEY_BITS.c \
    sysapi/sysapi_util/Unmarshal_TPMU_PUBLIC_PARMS.c \
    sysapi/sysapi_util/Marshal_TPMS_ECC_POINT.c \
    sysapi/sysapi_util/Unmarshal_TPMS_ECC_POINT.c \
    sysapi/sysapi_util/ConcatSizedByteBuffer.c \
    sysapi/sysapi_util/Unmarshal_TPMS_CERTIFY_INFO.c \
    sysapi/sysapi_util/marshal_uint32.c \
    sysapi/sysapi_util/Marshal_TPMA_ALGORITHM.c \
    sysapi/sysapi_util/Marshal_TPMS_SYMCIPHER_PARMS.c \
    sysapi/sysapi_util/Marshal_TPMT_KDF_SCHEME.c \
    sysapi/sysapi_util/Marshal_TPMA_SESSION.c \
    sysapi/sysapi_util/Unmarshal_TPML_ECC_CURVE.c \
    sysapi/sysapi_util/unmarshal_simple_tpm2b.c \
    sysapi/sysapi_util/Unmarshal_TPML_CC.c \
    sysapi/sysapi_util/Unmarshal_TPMS_TAGGED_PROPERTY.c \
    sysapi/sysapi_util/Marshal_TPMU_SIG_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPMS_CLOCK_INFO.c \
    sysapi/sysapi_util/Marshal_TPMT_ECC_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPMT_SENSITIVE.c \
    sysapi/sysapi_util/Marshal_TPMU_SYM_MODE.c \
    sysapi/sysapi_util/Marshal_TPMA_OBJECT.c \
    sysapi/sysapi_util/Marshal_TPMS_NV_PUBLIC.c \
    sysapi/sysapi_util/Unmarshal_TPML_TAGGED_TPM_PROPERTY.c \
    sysapi/sysapi_util/Unmarshal_TPMA_OBJECT.c \
    sysapi/sysapi_util/Marshal_TPM2B_SENSITIVE_CREATE.c \
    sysapi/sysapi_util/Unmarshal_TPMS_ATTEST.c \
    sysapi/sysapi_util/Marshal_TPMT_SENSITIVE.c \
    sysapi/sysapi_util/Unmarshal_TPMS_SIGNATURE_ECC.c \
    sysapi/sysapi_util/Unmarshal_TPMS_CONTEXT_DATA.c \
    sysapi/sysapi_util/Unmarshal_TPMS_RSA_PARMS.c \
    sysapi/sysapi_util/Unmarshal_TPML_TAGGED_PCR_PROPERTY.c \
    sysapi/sysapi_util/Unmarshal_TPMA_NV.c \
    sysapi/sysapi_util/Marshal_TPM2B_ECC_POINT.c \
    sysapi/sysapi_util/debug.c \
    sysapi/sysapi_util/copymem.c \
    sysapi/sysapi_util/Marshal_TPML_DIGEST.c \
    sysapi/sysapi_util/Marshal_TPMT_PUBLIC_PARMS.c \
    sysapi/sysapi_util/Marshal_TPMT_TK_HASHCHECK.c \
    sysapi/sysapi_util/Unmarshal_TPMT_RSA_SCHEME.c \
    sysapi/sysapi_util/Marshal_TPMA_LOCALITY.c \
    sysapi/sysapi_util/Marshal_TPMS_AUTH_COMMAND.c \
    sysapi/sysapi_util/Unmarshal_TPMS_TIME_INFO.c \
    sysapi/sysapi_util/unmarshal_uint16.c \
    sysapi/sysapi_util/Unmarshal_TPMU_SIGNATURE.c \
    sysapi/sysapi_util/Unmarshal_TPMS_NV_PUBLIC.c \
    sysapi/sysapi_util/Unmarshal_TPMT_SIG_SCHEME.c \
    sysapi/sysapi_util/Marshal_TPMT_SYM_DEF.c \
    sysapi/sysapi_util/Unmarshal_TPMT_TK_AUTH.c \
    sysapi/sysapi_util/Unmarshal_TPMU_KDF_SCHEME.c \
    sysapi/sysapi_util/Unmarshal_TPMT_PUBLIC_PARMS.c \
    sysapi/sysapi_util/Unmarshal_TPMU_CAPABILITIES.c \
    sysapi/sysapi_util/Marshal_TPMS_SIGNATURE_RSA.c \
    sysapi/sysapi_util/Marshal_TPMA_NV.c \
    sysapi/sysapi_util/unmarshal_uint64.c \
    sysapi/sysapi_util/Unmarshal_TPMS_TIME_ATTEST_INFO.c \
    sysapi/sysapi_util/Marshal_TPMS_CONTEXT.c \
    sysapi/sysapi_util/Unmarshal_TPMT_SIGNATURE.c \
    sysapi/sysapi_util/Unmarshal_TPMU_PUBLIC_ID.c \
    sysapi/sysapi_util/marshal_uint64.c

SYSAPI_INC = \
    sysapi/include//tss2_tpm2_types.h \
    sysapi/include//tss2_sys_api_part3.h \
    sysapi/include//tss2_tcti.h \
    sysapi/include//basetypes.h \
    sysapi/include//tss2_tcti_util.h \
    sysapi/include//tpm20.h \
    sysapi/include//tss2_sysapi_util.h \
    sysapi/include//implementation.h \
    sysapi/include//tss2_common.h \
    sysapi/include//endianConv.h \
    sysapi/include//tss2_sys_api_marshalUnmarshal.h \
    sysapi/include//tss2_sys.h \
    sysapi/include//tpmb.h
