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

include src_vars.mk

ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS       = -I$(srcdir)/include -I$(srcdir)/sysapi/include
AM_CXXFLAGS     = $(AM_CFLAGS)

# stuff to build, what that stuff is, and where/if to install said stuff
noinst_PROGRAMS = $(tpmclient)
lib_LTLIBRARIES = $(libsapi) $(libtcti_device) $(libtcti_socket)
noinst_LTLIBRARIES = test/integration/libtest_utils.la
check_PROGRAMS = $(TESTS_UNIT) $(TESTS_INTEGRATION)

# unit tests
if UNIT
TESTS_UNIT  = \
    test/unit/CheckOverflow \
    test/unit/CommonPreparePrologue \
    test/unit/CopyCommandHeader \
    test/unit/GetNumHandles \
    test/unit/marshal-TPM2B-simple \
    test/unit/marshal-UINT16 \
    test/unit/marshal-UINT32 \
    test/unit/tcti-device \
    test/unit/unmarshal-UINT16 \
    test/unit/unmarshal-UINT32
endif #UNIT

TESTS_INTEGRATION = \
    test/integration/get-random \
    test/integration/self-test \
    test/integration/pcr-extension

TESTS = $(check_PROGRAMS)
CLEANFILES = \
    $(nodist_pkgconfig_DATA) \
    $(man3_MANS) \
    $(man7_MANS)

AM_TESTS_ENVIRONMENT = \
    export TPM20TEST_TCTI_NAME="socket"; \
    export TPM20TEST_SOCKET_ADDRESS="127.0.0.1"; \
    export TPM20TEST_SOCKET_PORT="2321";

# headers and where to install them
libsapidir      = $(includedir)/sapi
libsapi_HEADERS = $(srcdir)/include/sapi/*.h
libtctidir      = $(includedir)/tcti
libtcti_HEADERS = $(srcdir)/include/tcti/*.h
# pkg-config files
pkgconfigdir          = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = lib/sapi.pc lib/tcti-device.pc lib/tcti-socket.pc
# man pages / documentation
man3_MANS = man/man3/InitDeviceTcti.3 man/man3/InitSocketTcti.3
man7_MANS = man/man7/tcti-device.7 man/man7/tcti-socket.7

EXTRA_DIST = \
    man/InitDeviceTcti.3.in \
    man/tcti-device.7.in \
    man/tcti-socket.7.in

if UNIT
test_unit_tcti_device_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_tcti_device_LDADD   = $(CMOCKA_LIBS)
test_unit_tcti_device_LDFLAGS = -Wl,--wrap=read -Wl,-wrap=write
test_unit_tcti_device_SOURCES = tcti/commonchecks.c tcti/tcti_device.c \
    ./sysapi/sysapi_util/changeEndian.c test/unit/tcti-device.c

test_unit_CommonPreparePrologue_CFLAGS = $(CMOCKA_CFLAGS) -I$(srcdir)/include \
    -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_unit_CommonPreparePrologue_LDFLAGS = -Wl,--unresolved-symbols=ignore-all
test_unit_CommonPreparePrologue_LDADD = $(CMOCKA_LIBS)
test_unit_CommonPreparePrologue_SOURCES = \
    test/unit/CommonPreparePrologue.c sysapi/sysapi_util/CommandUtil.c \
    sysapi/sysapi/ContextManagement.c

test_unit_GetNumHandles_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include -I$(srcdir)/sysapi/include
test_unit_GetNumHandles_LDADD   = $(CMOCKA_LIBS)
test_unit_GetNumHandles_SOURCES = \
    test/unit/GetNumHandles.c sysapi/sysapi_util/GetNumHandles.c

test_unit_CopyCommandHeader_CFLAGS = $(CMOCKA_CFLAGS) -I$(srcdir)/include \
    -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_unit_CopyCommandHeader_LDFLAGS = -Wl,--unresolved-symbols=ignore-all
test_unit_CopyCommandHeader_LDADD = $(CMOCKA_LIBS)
test_unit_CopyCommandHeader_SOURCES = \
    test/unit/CopyCommandHeader.c sysapi/sysapi_util/CommandUtil.c \
    sysapi/sysapi/ContextManagement.c sysapi/sysapi_util/changeEndian.c

test_unit_marshal_UINT16_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_unit_marshal_UINT16_LDADD   = $(CMOCKA_LIBS)
test_unit_marshal_UINT16_SOURCES = \
    sysapi/sysapi_util/changeEndian.c \
    sysapi/sysapi_util/checkoverflow.c \
    sysapi/sysapi_util/marshal_uint16.c \
    test/unit/marshal-UINT16.c

test_unit_unmarshal_UINT16_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_unit_unmarshal_UINT16_LDADD   = $(CMOCKA_LIBS)
test_unit_unmarshal_UINT16_SOURCES = \
    sysapi/sysapi_util/changeEndian.c \
    sysapi/sysapi_util/checkoverflow.c \
    sysapi/sysapi_util/unmarshal_uint16.c \
    test/unit/unmarshal-UINT16.c

test_unit_marshal_UINT32_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_unit_marshal_UINT32_LDADD   = $(CMOCKA_LIBS)
test_unit_marshal_UINT32_SOURCES = \
    sysapi/sysapi_util/changeEndian.c \
    sysapi/sysapi_util/checkoverflow.c \
    sysapi/sysapi_util/marshal_uint32.c \
    test/unit/marshal-UINT32.c

test_unit_unmarshal_UINT32_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_unit_unmarshal_UINT32_LDADD   = $(CMOCKA_LIBS)
test_unit_unmarshal_UINT32_SOURCES = \
    sysapi/sysapi_util/changeEndian.c \
    sysapi/sysapi_util/checkoverflow.c \
    sysapi/sysapi_util/unmarshal_uint32.c \
    test/unit/unmarshal-UINT32.c

test_unit_marshal_TPM2B_simple_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_unit_marshal_TPM2B_simple_LDADD   = $(CMOCKA_LIBS)
test_unit_marshal_TPM2B_simple_SOURCES = \
    sysapi/sysapi_util/changeEndian.c \
    sysapi/sysapi_util/checkoverflow.c \
    sysapi/sysapi_util/marshal_uint8.c \
    sysapi/sysapi_util/unmarshal_uint8.c \
    sysapi/sysapi_util/marshal_uint16.c \
    sysapi/sysapi_util/unmarshal_uint16.c \
    sysapi/sysapi_util/marshal_uint32.c \
    sysapi/sysapi_util/CopySessionData.c \
    sysapi/sysapi_util/marshal_simple_tpm2b.c \
    sysapi/sysapi_util/unmarshal_simple_tpm2b.c \
    sysapi/sysapi_util/unmarshal_simple_tpm2b_no_size_check.c \
    test/unit/marshal-TPM2B-simple.c

test_unit_CheckOverflow_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_unit_CheckOverflow_LDADD   = $(CMOCKA_LIBS)
test_unit_CheckOverflow_SOURCES = \
    sysapi/sysapi_util/checkoverflow.c \
    test/unit/CheckOverflow.c
endif # UNIT

# how to build stuff
sysapi_libsapi_la_CFLAGS  = -I$(srcdir)/sysapi/include $(AM_CFLAGS)
sysapi_libsapi_la_LDFLAGS = $(LIBRARY_LDFLAGS)
sysapi_libsapi_la_SOURCES = $(SYSAPI_C) $(SYSAPIUTIL_C)

tcti_libtcti_device_la_CFLAGS   = $(TCTIDEVICE_INC) $(AM_CFLAGS)
tcti_libtcti_device_la_LDFLAGS  = $(LIBRARY_LDFLAGS) \
    -Wl,--version-script=$(srcdir)/tcti/tcti_device.map
tcti_libtcti_device_la_SOURCES  = $(TCTIDEVICE_C) \
    sysapi/sysapi_util/changeEndian.c $(TCTICOMMON_C) common/debug.c

tcti_libtcti_socket_la_CFLAGS   = $(TCTISOCKET_INC) $(AM_CFLAGS)
tcti_libtcti_socket_la_CXXFLAGS = $(TCTISOCKET_INC) $(AM_CXXFLAGS)
tcti_libtcti_socket_la_LDFLAGS  = $(LIBRARY_LDFLAGS) \
    -Wl,--version-script=$(srcdir)/tcti/tcti_socket.map
tcti_libtcti_socket_la_SOURCES  =  $(TCTISOCKET_C) \
    sysapi/sysapi_util/changeEndian.c $(TCTISOCKET_CXX) $(TCTICOMMON_C) \
    common/sockets.cpp common/debug.c

test_tpmclient_tpmclient_CFLAGS   = $(TPMCLIENT_INC) $(AM_CFLAGS)
test_tpmclient_tpmclient_CXXFLAGS = $(TPMCLIENT_INC) $(TCTICOMMON_INC) $(TCTIDEVICE_INC) $(AM_CXXFLAGS) -DNO_RM_TESTS
test_tpmclient_tpmclient_LDADD    = $(libsapi) $(libtcti_socket) $(libtcti_device)
test_tpmclient_tpmclient_SOURCES  = $(TPMCLIENT_CXX) $(COMMON_C) $(SAMPLE_C)

test_integration_libtest_utils_la_SOURCES = test/integration/test-options.c \
    test/integration/context-util.c

test_integration_get_random_LDADD   = $(TESTS_LDADD)
test_integration_get_random_SOURCES = test/integration/get-random.c \
    test/integration/main.c

test_integration_self_test_LDADD   = $(TESTS_LDADD)
test_integration_self_test_SOURCES = test/integration/self-test.c \
    test/integration/main.c

test_integration_pcr_extension_LDADD   = $(TESTS_LDADD)
test_integration_pcr_extension_SOURCES = test/integration/pcr-extension.c \
    test/integration/main.c

TESTS_LDADD = $(noinst_LTLIBRARIES) $(lib_LTLIBRARIES)

%.pc : %.pc.in
	$(call make_parent_dir,$@)
	sed -e "s,[@]VERSION[@],$(PACKAGE_VERSION),g; \
	        s,[@]includedir[@],$(includedir),g;" $^ > $@

man/man3/%.3 : man/%.3.in $(srcdir)/man/man-postlude.troff
	$(call make_man,$@,$<,$(srcdir)/man/man-postlude.troff)

man/man7/%.7 : man/%.7.in $(srcdir)/man/man-postlude.troff
	$(call make_man,$@,$<,$(srcdir)/man/man-postlude.troff)

LIBRARY_LDFLAGS = -fPIC -Wl,--no-undefined

# simulator build / run scripts
CLEANFILES += test/simulator-build.sh test/simulator-run.sh test/simulator.inc
.PHONY = simulator-build simulator-start simulator-stop clean-local-ibmtpm
clean-local : clean-local-ibmtpm
clean-local-ibmtpm :
	rm -rf test/ibmtpm*

test/simulator.inc : $(srcdir)/script/simulator.inc
	cp $< $@
test/simulator-build.sh : $(srcdir)/script/simulator-build.sh
	cp $< $@
	chmod 755 $@
simulator-build : test/simulator-build.sh test/simulator.inc
	test/simulator-build.sh
test/simulator-run.sh : $(srcdir)/script/simulator-run.sh
	cp $< $@
	chmod 755 $@
simulator-start : test/simulator-run.sh test/simulator.inc
	test/simulator-run.sh start
simulator-stop : test/simulator-run.sh test/simulator.inc
	test/simulator-run.sh stop

# simple variables
TCTICOMMON_INC = -I$(srcdir)/include -I$(srcdir)/common \
    -I$(srcdir)/sysapi/include
TCTICOMMON_C   = tcti/commonchecks.c

TCTIDEVICE_INC = $(TCTICOMMON_INC)
TCTIDEVICE_C   = tcti/tcti_device.c

TCTISOCKET_INC = $(TCTICOMMON_INC)
TCTISOCKET_C   = tcti/platformcommand.c
TCTISOCKET_CXX = tcti/tcti_socket.cpp

TPMCLIENT_INC = -I$(srcdir)/include -I$(srcdir)/common \
    -I$(srcdir)/test/tpmclient -I$(srcdir)/sysapi/include \
    -I$(srcdir)/test/common/sample
TPMCLIENT_CXX = test/tpmclient/tpmclient.cpp

libsapi = sysapi/libsapi.la
libtcti_device = tcti/libtcti-device.la
libtcti_socket = tcti/libtcti-socket.la
tpmclient   = test/tpmclient/tpmclient

define make_parent_dir
    if [ ! -d $(dir $1) ]; then mkdir -p $(dir $1); fi
endef
# function to transform man .in files to man pages
# $1: target
# $2: .in file
# $3: man postlude file
define make_man
    $(call make_parent_dir,$1)
    cat $2 $3 > $1
    sed -i -e "s,[@]VERSION[@],$(PACKAGE_VERSION),g;" $1
endef
