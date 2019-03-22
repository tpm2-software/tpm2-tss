# SPDX-License-Identifier: BSD-2
# Copyright (c) 2015 - 2018 Intel Corporation
# Copyright (c) 2018 Fraunhofer SIT sponsored by Infineon Technologies AG
# All rights reserved.

### Initialize global variables used throughout the file ###
INCLUDE_DIRS    = -I$(srcdir)/src -I$(srcdir)/include/tss2
ACLOCAL_AMFLAGS = -I m4 --install
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS      = $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)

# Initialize empty variables to be extended throughout
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST =
CLEANFILES =
MOSTLYCLEANFILES =
noinst_PROGRAMS =

### Add ax_* rules ###
# ax_code_coverage
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

# ax_valgrind_check
@VALGRIND_CHECK_RULES@

# ax_doxygen
@DX_RULES@
MOSTLYCLEANFILES += $(DX_CLEANFILES)

if DOXYMAN
DOXYMAN3 = \
    doxygen-doc/man/ESYS_CONTEXT.3 \
    doxygen-doc/man/ESYS_TR.3 \
    doxygen-doc/man/ESYS_TR_defines.3 \
    doxygen-doc/man/Esys_ActivateCredential.3 \
    doxygen-doc/man/Esys_Certify.3 \
    doxygen-doc/man/Esys_CertifyCreation.3 \
    doxygen-doc/man/Esys_ChangeEPS.3 \
    doxygen-doc/man/Esys_ChangePPS.3 \
    doxygen-doc/man/Esys_Clear.3 \
    doxygen-doc/man/Esys_ClearControl.3 \
    doxygen-doc/man/Esys_ClockRateAdjust.3 \
    doxygen-doc/man/Esys_ClockSet.3 \
    doxygen-doc/man/Esys_Commit.3 \
    doxygen-doc/man/Esys_ContextLoad.3 \
    doxygen-doc/man/Esys_ContextSave.3 \
    doxygen-doc/man/Esys_Create.3 \
    doxygen-doc/man/Esys_CreatePrimary.3 \
    doxygen-doc/man/Esys_DictionaryAttackLockReset.3 \
    doxygen-doc/man/Esys_DictionaryAttackParameters.3 \
    doxygen-doc/man/Esys_Duplicate.3 \
    doxygen-doc/man/Esys_ECC_Parameters.3 \
    doxygen-doc/man/Esys_ECDH_KeyGen.3 \
    doxygen-doc/man/Esys_ECDH_ZGen.3 \
    doxygen-doc/man/Esys_EC_Ephemeral.3 \
    doxygen-doc/man/Esys_EncryptDecrypt.3 \
    doxygen-doc/man/Esys_EventSequenceComplete.3 \
    doxygen-doc/man/Esys_EvictControl.3 \
    doxygen-doc/man/Esys_FlushContext.3 \
    doxygen-doc/man/Esys_GetCapability.3 \
    doxygen-doc/man/Esys_GetCommandAuditDigest.3 \
    doxygen-doc/man/Esys_GetRandom.3 \
    doxygen-doc/man/Esys_GetSessionAuditDigest.3 \
    doxygen-doc/man/Esys_GetTestResult.3 \
    doxygen-doc/man/Esys_GetTime.3 \
    doxygen-doc/man/Esys_Hash.3 \
    doxygen-doc/man/Esys_HashSequenceStart.3 \
    doxygen-doc/man/Esys_HierarchyChangeAuth.3 \
    doxygen-doc/man/Esys_HierarchyControl.3 \
    doxygen-doc/man/Esys_HMAC.3 \
    doxygen-doc/man/Esys_HMAC_Start.3 \
    doxygen-doc/man/Esys_Import.3 \
    doxygen-doc/man/Esys_IncrementalSelfTest.3 \
    doxygen-doc/man/Esys_Load.3 \
    doxygen-doc/man/Esys_LoadExternal.3 \
    doxygen-doc/man/Esys_MakeCredential.3 \
    doxygen-doc/man/Esys_NV_Certify.3 \
    doxygen-doc/man/Esys_NV_ChangeAuth.3 \
    doxygen-doc/man/Esys_NV_DefineSpace.3 \
    doxygen-doc/man/Esys_NV_Extend.3 \
    doxygen-doc/man/Esys_NV_GlobalWriteLock.3 \
    doxygen-doc/man/Esys_NV_Increment.3 \
    doxygen-doc/man/Esys_NV_Read.3 \
    doxygen-doc/man/Esys_NV_ReadLock.3 \
    doxygen-doc/man/Esys_NV_ReadPublic.3 \
    doxygen-doc/man/Esys_NV_SetBits.3 \
    doxygen-doc/man/Esys_NV_UndefineSpace.3 \
    doxygen-doc/man/Esys_NV_UndefineSpaceSpecial.3 \
    doxygen-doc/man/Esys_NV_Write.3 \
    doxygen-doc/man/Esys_NV_WriteLock.3 \
    doxygen-doc/man/Esys_ObjectChangeAuth.3 \
    doxygen-doc/man/Esys_PCR_Allocate.3 \
    doxygen-doc/man/Esys_PCR_Event.3 \
    doxygen-doc/man/Esys_PCR_Extend.3 \
    doxygen-doc/man/Esys_PCR_Read.3 \
    doxygen-doc/man/Esys_PCR_Reset.3 \
    doxygen-doc/man/Esys_PCR_SetAuthPolicy.3 \
    doxygen-doc/man/Esys_PCR_SetAuthValue.3 \
    doxygen-doc/man/Esys_PolicyAuthorize.3 \
    doxygen-doc/man/Esys_PolicyAuthValue.3 \
    doxygen-doc/man/Esys_PolicyCommandCode.3 \
    doxygen-doc/man/Esys_PolicyCounterTimer.3 \
    doxygen-doc/man/Esys_PolicyCpHash.3 \
    doxygen-doc/man/Esys_PolicyDuplicationSelect.3 \
    doxygen-doc/man/Esys_PolicyGetDigest.3 \
    doxygen-doc/man/Esys_PolicyLocality.3 \
    doxygen-doc/man/Esys_PolicyNameHash.3 \
    doxygen-doc/man/Esys_PolicyNV.3 \
    doxygen-doc/man/Esys_PolicyNvWritten.3 \
    doxygen-doc/man/Esys_PolicyOR.3 \
    doxygen-doc/man/Esys_PolicyPassword.3 \
    doxygen-doc/man/Esys_PolicyPCR.3 \
    doxygen-doc/man/Esys_PolicyPhysicalPresence.3 \
    doxygen-doc/man/Esys_PolicyRestart.3 \
    doxygen-doc/man/Esys_PolicySecret.3 \
    doxygen-doc/man/Esys_PolicySigned.3 \
    doxygen-doc/man/Esys_PolicyTicket.3 \
    doxygen-doc/man/Esys_PP_Commands.3 \
    doxygen-doc/man/Esys_Quote.3 \
    doxygen-doc/man/Esys_ReadClock.3 \
    doxygen-doc/man/Esys_ReadPublic.3 \
    doxygen-doc/man/Esys_Rewrap.3 \
    doxygen-doc/man/Esys_RSA_Decrypt.3 \
    doxygen-doc/man/Esys_RSA_Encrypt.3 \
    doxygen-doc/man/Esys_SelfTest.3 \
    doxygen-doc/man/Esys_SequenceComplete.3 \
    doxygen-doc/man/Esys_SequenceUpdate.3 \
    doxygen-doc/man/Esys_SetAlgorithmSet.3 \
    doxygen-doc/man/Esys_SetCommandCodeAuditStatus.3 \
    doxygen-doc/man/Esys_SetPrimaryPolicy.3 \
    doxygen-doc/man/Esys_Shutdown.3 \
    doxygen-doc/man/Esys_Sign.3 \
    doxygen-doc/man/Esys_StartAuthSession.3 \
    doxygen-doc/man/Esys_Startup.3 \
    doxygen-doc/man/Esys_StirRandom.3 \
    doxygen-doc/man/Esys_TestParms.3 \
    doxygen-doc/man/Esys_Unseal.3 \
    doxygen-doc/man/Esys_Vendor_TCG_Test.3 \
    doxygen-doc/man/Esys_VerifySignature.3 \
    doxygen-doc/man/Esys_ZGen_2Phase.3
$(DOXYMAN3): doxygen-doc
else #DOXYMAN
DOXYMAN3 =
endif #DOXYMAN

### Include make files ###
# Add source code files from bootstrap
include src_vars.mk

# Add test definitions
include Makefile-test.am

# Add fuzz definitions
include Makefile-fuzz.am

### Distribution files ###
# Add udev rule
udevrules_DATA   = dist/tpm-udev.rules

# Adding user and developer information
EXTRA_DIST += \
    CHANGELOG.md \
    CONTRIBUTING.md \
    INSTALL.md \
    LICENSE \
    README.md \
    RELEASE.md

# Generate the AUTHORS file from git log
AUTHORS :
	$(AM_V_GEN)git log --format='%aN <%aE>' | grep -v 'users.noreply.github.com' | sort | \
	    uniq -c | sort -nr | sed 's/^\s*//' | cut -d" " -f2- > $@
EXTRA_DIST += AUTHORS
CLEANFILES += AUTHORS

# pkg-config setup. pc-file declarations happen in the corresponding modules
pkgconfigdir          = $(libdir)/pkgconfig
pkgconfig_DATA =
CLEANFILES += $(pkgconfig_DATA)

%.pc : %.pc.in
	$(AM_V_GEN)$(call make_parent_dir,$@) && \
	sed -e "s,[@]VERSION[@],$(PACKAGE_VERSION),g; \
	        s,[@]libdir[@],$(libdir),g; \
	        s,[@]includedir[@],$(includedir),g;" $^ > $@

# Base TSS2 headers
tss2dir = $(includedir)/tss2
tss2_HEADERS = \
    $(srcdir)/include/tss2/tss2_common.h \
    $(srcdir)/include/tss2/tss2_tcti.h \
    $(srcdir)/include/tss2/tss2_tpm2_types.h

### Internal utility library
libutil = libutil.la
noinst_LTLIBRARIES += $(libutil)
libutil_la_SOURCES = $(UTIL_SRC)

### TCG TSS Marshaling/Unmarshaling spec library ###
libtss2_mu = src/tss2-mu/libtss2-mu.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_mu.h
lib_LTLIBRARIES += $(libtss2_mu)
pkgconfig_DATA += lib/tss2-mu.pc
EXTRA_DIST += lib/tss2-mu.map lib/tss2-mu.pc.in

if HAVE_LD_VERSION_SCRIPT
src_tss2_mu_libtss2_mu_la_LDFLAGS = -Wl,--version-script=$(srcdir)/lib/tss2-mu.map
endif # HAVE_LD_VERSION_SCRIPT
src_tss2_mu_libtss2_mu_la_LIBADD = $(libutil)
src_tss2_mu_libtss2_mu_la_SOURCES = $(TSS2_MU_SRC)

### TCG TSS TCTI spec libraries ###
# tcti device library
if ENABLE_TCTI_DEVICE
libtss2_tcti_device = src/tss2-tcti/libtss2-tcti-device.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_tcti_device.h
lib_LTLIBRARIES += $(libtss2_tcti_device)
pkgconfig_DATA += lib/tss2-tcti-device.pc
EXTRA_DIST += lib/tss2-tcti-device.map lib/tss2-tcti-device.pc.in

if HAVE_LD_VERSION_SCRIPT
src_tss2_tcti_libtss2_tcti_device_la_LDFLAGS  = -Wl,--version-script=$(srcdir)/lib/tss2-tcti-device.map
endif # HAVE_LD_VERSION_SCRIPT
src_tss2_tcti_libtss2_tcti_device_la_LIBADD   = $(libtss2_mu) $(libutil)
src_tss2_tcti_libtss2_tcti_device_la_SOURCES  = \
    src/tss2-tcti/tcti-common.c \
    src/tss2-tcti/tcti-device.c
endif # ENABLE_TCTI_DEVICE

# tcti library for Microsoft TPM2 simulator
if ENABLE_TCTI_MSSIM
libtss2_tcti_mssim = src/tss2-tcti/libtss2-tcti-mssim.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_tcti_mssim.h
lib_LTLIBRARIES += $(libtss2_tcti_mssim)
pkgconfig_DATA += lib/tss2-tcti-mssim.pc
EXTRA_DIST += lib/tss2-tcti-mssim.map lib/tss2-tcti-mssim.pc.in

if HAVE_LD_VERSION_SCRIPT
src_tss2_tcti_libtss2_tcti_mssim_la_LDFLAGS  = -Wl,--version-script=$(srcdir)/lib/tss2-tcti-mssim.map
endif # HAVE_LD_VERSION_SCRIPT
src_tss2_tcti_libtss2_tcti_mssim_la_LIBADD   = $(libtss2_mu) $(libutil)
src_tss2_tcti_libtss2_tcti_mssim_la_SOURCES  = \
    src/tss2-tcti/tcti-common.c \
    src/tss2-tcti/tcti-mssim.c
endif # ENABLE_TCTI_MSSIM

### TCG TSS SAPI spec library ###
libtss2_sys = src/tss2-sys/libtss2-sys.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_sys.h
lib_LTLIBRARIES += $(libtss2_sys)
pkgconfig_DATA += lib/tss2-sys.pc
EXTRA_DIST += lib/tss2-sys.pc.in

src_tss2_sys_libtss2_sys_la_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/src/tss2-sys
src_tss2_sys_libtss2_sys_la_LDFLAGS = $(AM_LDFLAGS) $(LIBSOCKET_LDFLAGS)
src_tss2_sys_libtss2_sys_la_LIBADD = $(libtss2_mu) $(libutil)
src_tss2_sys_libtss2_sys_la_SOURCES = $(TSS2_SYS_SRC)

### TCG TSS ESAPI spec library ###
if ESAPI
libtss2_esys = src/tss2-esys/libtss2-esys.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_esys.h
lib_LTLIBRARIES += $(libtss2_esys)
pkgconfig_DATA += lib/tss2-esys.pc
EXTRA_DIST += lib/tss2-esys.pc.in


src_tss2_esys_libtss2_esys_la_LIBADD  = $(libtss2_sys) $(libtss2_mu) \
    $(libtss2_tcti_device) $(libtss2_tcti_mssim) $(libutil)

if ESYS_OSSL
TSS2_ESYS_SRC += src/tss2-esys/esys_crypto_ossl.h src/tss2-esys/esys_crypto_ossl.c
src_tss2_esys_libtss2_esys_la_CFLAGS  = $(AM_CFLAGS) -I$(srcdir)/src/tss2-esys -DOSSL
src_tss2_esys_libtss2_esys_la_LDFLAGS = $(AM_LDFLAGS) $(LIBDL_LDFLAGS) $(LIBSOCKET_LDFLAGS) -lssl -lcrypto
else
if ESYS_GCRYPT
TSS2_ESYS_SRC += src/tss2-esys/esys_crypto_gcrypt.h src/tss2-esys/esys_crypto_gcrypt.c
src_tss2_esys_libtss2_esys_la_CFLAGS  = $(AM_CFLAGS) -I$(srcdir)/src/tss2-esys
src_tss2_esys_libtss2_esys_la_LDFLAGS = $(AM_LDFLAGS) $(LIBDL_LDFLAGS) $(LIBSOCKET_LDFLAGS) -lgcrypt
endif
endif
src_tss2_esys_libtss2_esys_la_SOURCES = $(TSS2_ESYS_SRC)

endif #ESAPI

### Man Pages
man3_MANS = man/man3/Tss2_Tcti_Device_Init.3 man/man3/Tss2_Tcti_Mssim_Init.3 $(DOXYMAN3)
man7_MANS = man/man7/tss2-tcti-device.7 man/man7/tss2-tcti-mssim.7

man/man3/%.3 : man/%.3.in $(srcdir)/man/man-postlude.troff
	$(AM_V_GEN)$(call make_man,$@,$<,$(srcdir)/man/man-postlude.troff)

man/man7/%.7 : man/%.7.in $(srcdir)/man/man-postlude.troff
	$(AM_V_GEN)$(call make_man,$@,$<,$(srcdir)/man/man-postlude.troff)

EXTRA_DIST += dist/tpm-udev.rules

if WITH_UDEVRULESPREFIX
install-data-hook:
	mv $(DESTDIR)$(udevrulesdir)/tpm-udev.rules $(DESTDIR)$(udevrulesdir)/$(udevrulesprefix)tpm-udev.rules

uninstall-local:
	-rm $(DESTDIR)$(udevrulesdir)/$(udevrulesprefix)tpm-udev.rules
endif

EXTRA_DIST += \
    doc/doxygen.dox \
    doc/coding_standard_c.md \
    doc/logging.md \
    doc/fuzzing.md \
    man/man-postlude.troff \
    man/Tss2_Tcti_Device_Init.3.in \
    man/Tss2_Tcti_Mssim_Init.3.in \
    man/tss2-tcti-device.7.in \
    man/tss2-tcti-mssim.7.in

CLEANFILES += \
    $(man3_MANS) \
    $(man7_MANS)

### Helper Functions ###
define make_parent_dir
    if [ ! -d $(dir $1) ]; then mkdir -p $(dir $1); fi
endef

# function to transform man .in files to man pages
# $1: target
# $2: .in file
# $3: man postlude file
define make_man
    $(call make_parent_dir,$1) && \
    cat $2 $3 > $1 && \
    sed -i -e "s,[@]VERSION[@],$(PACKAGE_VERSION),g;" $1
endef
