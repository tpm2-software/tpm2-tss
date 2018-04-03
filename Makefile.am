#;**********************************************************************;
# Copyright (c) 2015 - 2018 Intel Corporation
# Copyright (c) 2018 Fraunhofer SIT sponsored by Infineon Technologies AG
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

### Initialize global variables used throughout the file ###
INCLUDE_DIRS    = -I$(srcdir)/src -I$(srcdir)/include/tss2
ACLOCAL_AMFLAGS = -I m4
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
@CODE_COVERAGE_RULES@

# ax_doxygen
@DX_RULES@
MOSTLYCLEANFILES += $(DX_CLEANFILES)

### Include make files ###
# Add source code files from bootstrap
include src_vars.mk

# Add test definitions
include Makefile-test.am

### Distributiuon files ###
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
nodist_pkgconfig_DATA =
CLEANFILES += $(nodist_pkgconfig_DATA)

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
libutil_la_CFLAGS = $(AM_CFLAGS)
libutil_la_SOURCES = $(UTIL_SRC)

### TCG TSS Marshaling/Unmarshalling spec library ###
libtss2_mu = src/tss2-mu/libtss2-mu.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_mu.h
lib_LTLIBRARIES += $(libtss2_mu)
nodist_pkgconfig_DATA += lib/tss2-mu.pc
EXTRA_DIST += lib/tss2-mu.map lib/tss2-mu.pc.in

if HAVE_LD_VERSION_SCRIPT
src_tss2_mu_libtss2_mu_la_LDFLAGS = -Wl,--version-script=$(srcdir)/lib/tss2-mu.map
endif # HAVE_LD_VERSION_SCRIPT
src_tss2_mu_libtss2_mu_la_LIBADD = $(libutil)
src_tss2_mu_libtss2_mu_la_SOURCES = $(TSS2_MU_SRC)

### TCG TSS TCTI spec libraries ###
# tcti device library
libtss2_tcti_device = src/tss2-tcti/libtss2-tcti-device.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_tcti_device.h
lib_LTLIBRARIES += $(libtss2_tcti_device)
nodist_pkgconfig_DATA += lib/tss2-tcti-device.pc
EXTRA_DIST += lib/tss2-tcti-device.map lib/tss2-tcti-device.pc.in

src_tss2_tcti_libtss2_tcti_device_la_CFLAGS   = $(AM_CFLAGS)
if HAVE_LD_VERSION_SCRIPT
src_tss2_tcti_libtss2_tcti_device_la_LDFLAGS  = -Wl,--version-script=$(srcdir)/lib/tss2-tcti-device.map
endif # HAVE_LD_VERSION_SCRIPT
src_tss2_tcti_libtss2_tcti_device_la_LIBADD   = $(libtss2_mu) $(libutil)
src_tss2_tcti_libtss2_tcti_device_la_SOURCES  = \
    src/tss2-tcti/tcti-common.c src/tss2-tcti/tcti-common.h \
    src/tss2-tcti/tcti-device.c src/tss2-tcti/tcti-device.h

# tcti library for microsoft simulator
libtss2_tcti_mssim = src/tss2-tcti/libtss2-tcti-mssim.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_tcti_mssim.h
lib_LTLIBRARIES += $(libtss2_tcti_mssim)
nodist_pkgconfig_DATA += lib/tss2-tcti-mssim.pc
EXTRA_DIST += lib/tss2-tcti-mssim.map lib/tss2-tcti-mssim.pc.in

src_tss2_tcti_libtss2_tcti_mssim_la_CFLAGS   = $(AM_CFLAGS) $(URIPARSER_CFLAGS)
if HAVE_LD_VERSION_SCRIPT
src_tss2_tcti_libtss2_tcti_mssim_la_LDFLAGS  = -Wl,--version-script=$(srcdir)/lib/tss2-tcti-mssim.map
endif # HAVE_LD_VERSION_SCRIPT
src_tss2_tcti_libtss2_tcti_mssim_la_LIBADD   = $(libtss2_mu) $(URIPARSER_LIBS) $(libutil)
src_tss2_tcti_libtss2_tcti_mssim_la_SOURCES  = \
    src/tss2-tcti/tcti-common.c src/tss2-tcti/tcti-common.h \
    src/tss2-tcti/tcti-mssim.c src/tss2-tcti/tcti-mssim.h

### TCG TSS SAPI spec library ###
libtss2_sys = src/tss2-sys/libtss2-sys.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_sys.h
lib_LTLIBRARIES += $(libtss2_sys)
nodist_pkgconfig_DATA += lib/tss2-sys.pc
EXTRA_DIST += lib/tss2-sys.pc.in

src_tss2_sys_libtss2_sys_la_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/src/tss2-sys
src_tss2_sys_libtss2_sys_la_LIBADD = $(libtss2_mu) $(libutil)
src_tss2_sys_libtss2_sys_la_SOURCES = $(TSS2_SYS_SRC)

### TCG TSS ESAPI spec library ###
if ESAPI
libtss2_esys = src/tss2-esys/libtss2-esys.la
tss2_HEADERS += $(srcdir)/include/tss2/tss2_esys.h
lib_LTLIBRARIES += $(libtss2_esys)
nodist_pkgconfig_DATA += lib/tss2-esys.pc
EXTRA_DIST += lib/tss2-esys.pc.in

src_tss2_esys_libtss2_esys_la_CFLAGS  = $(AM_CFLAGS) -I$(srcdir)/src/tss2-esys
src_tss2_esys_libtss2_esys_la_LIBADD  = $(libtss2_sys) $(libtss2_mu) \
    $(libtss2_tcti_device) $(libtss2_tcti_mssim) $(libutil)
src_tss2_esys_libtss2_esys_la_LDFLAGS = $(AM_LDFLAGS) -ldl -lgcrypt
src_tss2_esys_libtss2_esys_la_SOURCES = $(TSS2_ESYS_SRC)

endif #ESAPI

### Man Pages
man3_MANS = man/man3/Tss2_Tcti_Device_Init.3 man/man3/Tss2_Tcti_Mssim_Init.3
man7_MANS = man/man7/tss2-tcti-device.7 man/man7/tss2-tcti-mssim.7

man/man3/%.3 : man/%.3.in $(srcdir)/man/man-postlude.troff
	$(AM_V_GEN)$(call make_man,$@,$<,$(srcdir)/man/man-postlude.troff)

man/man7/%.7 : man/%.7.in $(srcdir)/man/man-postlude.troff
	$(AM_V_GEN)$(call make_man,$@,$<,$(srcdir)/man/man-postlude.troff)

EXTRA_DIST += \
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
