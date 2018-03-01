#;**********************************************************************;
# Copyright (c) 2015, 2016, 2017 Intel Corporation
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
INCLUDE_DIRS    = -I$(srcdir)/include -I$(srcdir)/sysapi/include -I$(srcdir)/marshal
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS      = $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)

# Initialize empty variables to be extended throughout
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST =
CLEANFILES =
MOSTLYCLEANFILES =

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

### Internal utility library
libutil = libutil.la
noinst_LTLIBRARIES += $(libutil)
libutil_la_CFLAGS = $(AM_CFLAGS)
libutil_la_SOURCES = log/log.c log/log.h tcti/tcti.c tcti/tcti.h

### TCG TSS Marshaling/Unmarshalling spec library ###
libmarshal = marshal/libmarshal.la
lib_LTLIBRARIES += $(libmarshal)

if HAVE_LD_VERSION_SCRIPT
marshal_libmarshal_la_LDFLAGS = -Wl,--version-script=$(srcdir)/lib/libmarshal.map
endif # HAVE_LD_VERSION_SCRIPT
marshal_libmarshal_la_LIBADD = $(libutil)
marshal_libmarshal_la_SOURCES = $(MARSHAL_SRC)

nodist_pkgconfig_DATA += lib/marshal.pc
EXTRA_DIST += \
    lib/libmarshal.map \
    lib/marshal.pc.in

### TCG TSS TCTI spec libraries ###
# tcti headers
libtctidir      = $(includedir)/tcti
libtcti_HEADERS = $(srcdir)/include/tcti/*.h

# tcti device library
lib_LTLIBRARIES += tcti/libtcti-device.la

tcti_libtcti_device_la_CFLAGS   = $(AM_CFLAGS)
if HAVE_LD_VERSION_SCRIPT
tcti_libtcti_device_la_LDFLAGS  = -Wl,--version-script=$(srcdir)/tcti/tcti_device.map
endif # HAVE_LD_VERSION_SCRIPT
tcti_libtcti_device_la_LIBADD   = $(libmarshal) $(libutil)
tcti_libtcti_device_la_SOURCES  = tcti/tcti_device.c

nodist_pkgconfig_DATA += lib/tcti-device.pc
EXTRA_DIST += \
    tcti/tcti_device.map \
    lib/tcti-device.pc.in

# tcti socket library
libtcti_socket = tcti/libtcti-socket.la
lib_LTLIBRARIES += $(libtcti_socket)

tcti_libtcti_socket_la_CFLAGS   = $(AM_CFLAGS) $(URIPARSER_CFLAGS)
if HAVE_LD_VERSION_SCRIPT
tcti_libtcti_socket_la_LDFLAGS  = -Wl,--version-script=$(srcdir)/tcti/tcti_socket.map
endif # HAVE_LD_VERSION_SCRIPT
tcti_libtcti_socket_la_LIBADD   = $(libmarshal) $(URIPARSER_LIBS) $(libutil)
tcti_libtcti_socket_la_SOURCES  = tcti/platformcommand.c tcti/tcti_socket.c \
    tcti/sockets.c tcti/sockets.h

nodist_pkgconfig_DATA += lib/tcti-socket.pc
EXTRA_DIST += \
    tcti/tcti_socket.map \
    lib/tcti-socket.pc.in

### TCG TSS SAPI spec library ###
# Headers
libsapidir      = $(includedir)/sapi
libsapi_HEADERS = $(srcdir)/include/sapi/*.h

# Library
libsapi = sysapi/libsapi.la
lib_LTLIBRARIES += $(libsapi)
sysapi_libsapi_la_LIBADD  = $(libmarshal)
sysapi_libsapi_la_SOURCES = $(SYSAPI_C) $(SYSAPI_H) $(SYSAPIUTIL_C) \
    $(SYSAPIUTIL_H)

nodist_pkgconfig_DATA += lib/sapi.pc

EXTRA_DIST += \
    lib/sapi.pc.in

### TCG TSS ESAPI spec library ###
if ESAPI
# Headers
libesapidir      = $(includedir)/esapi
libesapi_HEADERS = $(srcdir)/include/esapi/*.h

# Library
libesapi = esapi/libesapi.la
lib_LTLIBRARIES += $(libesapi)
esapi_libesapi_la_CFLAGS  = $(AM_CFLAGS) -Wno-unused-variable -Wno-unused-label \
                            -I. -I$(srcdir)/esapi/esapi -I$(srcdir)/include/esapi \
                            -I$(srcdir)/esapi/esapi_util \
                            -DESYS_TCTI_DEFAULT_MODULE=$(TCTI_DEFAULT_MODULE) \
                            -DESYS_TCTI_DEFAULT_CONFIG=$(TCTI_DEFAULT_CONFIG)
esapi_libesapi_la_LIBADD  = $(libsapi) $(libmarshal) $(libtcti_device) $(libtcti_socket) $(libutil)
esapi_libesapi_la_LDFLAGS = $(AM_LDFLAGS)  -lgcrypt
esapi_libesapi_la_SOURCES = $(ESAPI_SRC)
endif #ESAPI

### Man Pages
man3_MANS = man/man3/InitDeviceTcti.3 man/man3/InitSocketTcti.3
man7_MANS = man/man7/tcti-device.7 man/man7/tcti-socket.7

man/man3/%.3 : man/%.3.in $(srcdir)/man/man-postlude.troff
	$(AM_V_GEN)$(call make_man,$@,$<,$(srcdir)/man/man-postlude.troff)

man/man7/%.7 : man/%.7.in $(srcdir)/man/man-postlude.troff
	$(AM_V_GEN)$(call make_man,$@,$<,$(srcdir)/man/man-postlude.troff)

EXTRA_DIST += \
    man/man-postlude.troff \
    man/InitDeviceTcti.3.in \
    man/InitSocketTcti.3.in \
    man/tcti-device.7.in \
    man/tcti-socket.7.in

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
