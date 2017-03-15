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

INCLUDE_DIRS    = -I$(srcdir)/include -I$(srcdir)/sysapi/include
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS)
AM_LDFLAGS      = $(EXTRA_LDFLAGS)

# stuff to build, what that stuff is, and where/if to install said stuff
sbin_PROGRAMS   = $(resourcemgr)
noinst_PROGRAMS = $(tpmclient) $(tpmtest)
lib_LTLIBRARIES = $(libmarshal) $(libsapi) $(libtcti_device) $(libtcti_socket)
noinst_LTLIBRARIES = test/integration/libtest_utils.la
check_PROGRAMS = $(TESTS_UNIT) $(TESTS_INTEGRATION)

# unit tests
if UNIT
TESTS_UNIT  = \
    test/unit/CommonPreparePrologue \
    test/unit/CopyCommandHeader \
    test/unit/getcommands-malloc-mock \
    test/unit/GetNumHandles \
    test/unit/marshal-TPM2B-simple \
    test/unit/tcti-device \
    test/unit/UINT8-marshal \
    test/unit/UINT16-marshal \
    test/unit/UINT32-marshal \
    test/unit/UINT64-marshal
endif #UNIT

TESTS_INTEGRATION = \
    test/integration/get-random \
    test/integration/self-test \
    test/integration/pcr-extension \
    test/integration/asymmetric-encrypt-decrypt \
    test/integration/start-auth-session

TESTS = $(check_PROGRAMS)
CLEANFILES = $(nodist_pkgconfig_DATA)

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

if UNIT
test_unit_tcti_device_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_tcti_device_LDADD   = $(CMOCKA_LIBS) $(libmarshal)
test_unit_tcti_device_LDFLAGS = -Wl,--wrap=read -Wl,-wrap=write
test_unit_tcti_device_SOURCES = tcti/commonchecks.c tcti/tcti_device.c \
    test/unit/tcti-device.c

test_unit_getcommands_malloc_mock_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_getcommands_malloc_mock_LDADD   = $(CMOCKA_LIBS)
test_unit_getcommands_malloc_mock_LDFLAGS = -Wl,--wrap=malloc \
    -Wl,--wrap=Tss2_Sys_GetCapability
test_unit_getcommands_malloc_mock_SOURCES = \
    test/unit/getcommands-malloc-mock.c resourcemgr/getcommands.c

test_unit_CommonPreparePrologue_CFLAGS = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_CommonPreparePrologue_LDFLAGS = -Wl,--unresolved-symbols=ignore-all
test_unit_CommonPreparePrologue_LDADD = $(CMOCKA_LIBS) $(libsapi)
test_unit_CommonPreparePrologue_SOURCES = test/unit/CommonPreparePrologue.c

test_unit_GetNumHandles_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_GetNumHandles_LDADD   = $(CMOCKA_LIBS) $(libsapi)
test_unit_GetNumHandles_SOURCES = test/unit/GetNumHandles.c

test_unit_CopyCommandHeader_CFLAGS = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_CopyCommandHeader_LDFLAGS = -Wl,--unresolved-symbols=ignore-all
test_unit_CopyCommandHeader_LDADD = $(CMOCKA_LIBS) $(libsapi)
test_unit_CopyCommandHeader_SOURCES = test/unit/CopyCommandHeader.c

test_unit_marshal_TPM2B_simple_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_marshal_TPM2B_simple_LDADD   = $(CMOCKA_LIBS) $(libsapi)
test_unit_marshal_TPM2B_simple_SOURCES = test/unit/marshal-TPM2B-simple.c

test_unit_UINT8_marshal_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_UINT8_marshal_LDADD   = $(CMOCKA_LIBS) $(libmarshal)
test_unit_UINT8_marshal_SOURCES = test/unit/UINT8-marshal.c

test_unit_UINT16_marshal_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_UINT16_marshal_LDADD   = $(CMOCKA_LIBS) $(libmarshal)
test_unit_UINT16_marshal_SOURCES = test/unit/UINT16-marshal.c

test_unit_UINT32_marshal_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_UINT32_marshal_LDADD   = $(CMOCKA_LIBS) $(libmarshal)
test_unit_UINT32_marshal_SOURCES = test/unit/UINT32-marshal.c

test_unit_UINT64_marshal_CFLAGS  = $(CMOCKA_CFLAGS) $(AM_CFLAGS)
test_unit_UINT64_marshal_LDADD   = $(CMOCKA_LIBS) $(libmarshal)
test_unit_UINT64_marshal_SOURCES = test/unit/UINT64-marshal.c
endif # UNIT

# how to build stuff
resourcemgr_resourcemgr_CFLAGS   = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_LDADD    = $(libsapi) $(libtcti_device) $(libtcti_socket) $(libmarshal)
resourcemgr_resourcemgr_LDFLAGS  = $(PTHREAD_LDFLAGS)
resourcemgr_resourcemgr_SOURCES  = $(COMMON_SRC) resourcemgr/resourcemgr.c \
    resourcemgr/criticalsection_linux.c resourcemgr/getcommands.c

marshal_libmarshal_la_LDFLAGS = -Wl,--version-script=$(srcdir)/lib/libmarshal.map
marshal_libmarshal_la_SOURCES = marshal/base-types.c log/log.c

sysapi_libsapi_la_LIBADD  = $(libmarshal)
sysapi_libsapi_la_SOURCES = $(SYSAPI_C) $(SYSAPIUTIL_C)

tcti_libtcti_device_la_CFLAGS   = $(AM_CFLAGS)
tcti_libtcti_device_la_LDFLAGS  = -Wl,--version-script=$(srcdir)/tcti/tcti_device.map
tcti_libtcti_device_la_LIBADD   = $(libmarshal)
tcti_libtcti_device_la_SOURCES  = tcti/tcti_device.c tcti/commonchecks.c \
    common/debug.c

tcti_libtcti_socket_la_CFLAGS   = $(AM_CFLAGS)
tcti_libtcti_socket_la_LDFLAGS  = -Wl,--version-script=$(srcdir)/tcti/tcti_socket.map
tcti_libtcti_socket_la_SOURCES  = tcti/platformcommand.c tcti/tcti_socket.c \
    sysapi/sysapi_util/changeEndian.c tcti/commonchecks.c common/sockets.c \
    common/debug.c

test_tpmclient_tpmclient_LDADD    = $(libsapi) $(libtcti_socket) $(libtcti_device)
test_tpmclient_tpmclient_SOURCES  = test/tpmclient/tpmclient.c $(COMMON_C) $(SAMPLE_C)

test_tpmtest_tpmtest_LDADD    = $(libsapi) $(libtcti_socket) $(libtcti_device)
test_tpmtest_tpmtest_SOURCES  = test/tpmtest/tpmtest.c $(COMMON_C) $(SAMPLE_C)

test_integration_libtest_utils_la_SOURCES = test/integration/test-options.c \
    test/integration/context-util.c

test_integration_get_random_LDADD   = $(TESTS_LDADD)
test_integration_get_random_SOURCES = test/integration/get-random.c \
    test/integration/main.c

test_integration_self_test_LDADD   = $(TESTS_LDADD)
test_integration_self_test_SOURCES = test/integration/self-test.c \
    test/integration/main.c

test_integration_start_auth_session_LDADD = $(TESTS_LDADD)
test_integration_start_auth_session_SOURCES = test/integration/main.c \
    test/integration/start-auth-session.c

test_integration_pcr_extension_LDADD   = $(TESTS_LDADD)
test_integration_pcr_extension_SOURCES = test/integration/pcr-extension.c \
    test/integration/main.c

test_integration_asymmetric_encrypt_decrypt_LDADD   = $(TESTS_LDADD)
test_integration_asymmetric_encrypt_decrypt_SOURCES = test/integration/asymmetric-encrypt-decrypt.c \
    test/integration/main.c

TESTS_LDADD = $(noinst_LTLIBRARIES) $(lib_LTLIBRARIES)

%.pc : %.pc.in
	if [ ! -d $(dir $@) ]; then mkdir -p $(dir $@); fi
	sed -e "s,[@]VERSION[@],$(PACKAGE_VERSION),g; \
	        s,[@]includedir[@],$(includedir),g;" $^ > $@

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
libsapi = sysapi/libsapi.la
libtcti_device = tcti/libtcti-device.la
libtcti_socket = tcti/libtcti-socket.la
libmarshal = marshal/libmarshal.la
resourcemgr = resourcemgr/resourcemgr
tpmclient   = test/tpmclient/tpmclient
tpmtest     = test/tpmtest/tpmtest
