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
AM_CFLAGS       = -I$(srcdir)/include
AM_CXXFLAGS     = $(AM_CFLAGS)

# stuff to build, what that stuff is, and where/if to install said stuff
sbin_PROGRAMS   = $(resourcemgr)
noinst_PROGRAMS = $(tpmclient) $(tpmtest)
lib_LTLIBRARIES = $(libsapi) $(libtcti_device) $(libtcti_socket)
# unit tests
check_PROGRAMS  = \
    test/tcti_device \
    test/getcommands-malloc-mock_unit \
    test/CommonPreparePrologue_unit \
    test/GetNumHandles_unit
    test/CopyCommandHeader_unit
TESTS = $(check_PROGRAMS)
CLEANFILES = $(nodist_pkgconfig_DATA)

# headers and where to install them
libsapidir      = $(includedir)/sapi
libsapi_HEADERS = $(srcdir)/include/sapi/*.h
libtctidir      = $(includedir)/tcti
libtcti_HEADERS = $(srcdir)/include/tcti/*.h
# pkg-config files
pkgconfigdir          = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = lib/sapi.pc lib/tcti-device.pc lib/tcti-socket.pc

test_tcti_device_CFLAGS  = $(CMOCKA_CFLAGS) -I$(srcdir) -I$(srcdir)/sysapi/include
test_tcti_device_LDADD   = $(libsapi) $(libtcti_device) $(CMOCKA_LIBS)
test_tcti_device_SOURCES = test/tcti_device.c test/tcti_device_test.c

test_getcommands_malloc_mock_unit_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/sysapi/include/
test_getcommands_malloc_mock_unit_LDADD   = $(CMOCKA_LIBS)
test_getcommands_malloc_mock_unit_LDFLAGS = -Wl,--wrap=malloc \
    -Wl,--wrap=Tss2_Sys_GetCapability
test_getcommands_malloc_mock_unit_SOURCES = \
    test/getcommands-malloc-mock_unit.c resourcemgr/getcommands.c

test_CommonPreparePrologue_unit_CFLAGS = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_CommonPreparePrologue_unit_LDFLAGS = -Wl,--unresolved-symbols=ignore-all
test_CommonPreparePrologue_unit_LDADD = $(CMOCKA_LIBS)
test_CommonPreparePrologue_unit_SOURCES = \
    test/CommonPreparePrologue_unit.c sysapi/sysapi_util/CommandUtil.c \
    sysapi/sysapi/ContextManagement.c

test_GetNumHandles_unit_CFLAGS  = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include -I$(srcdir)/sysapi/include
test_GetNumHandles_unit_LDADD   = $(CMOCKA_LIBS)
test_GetNumHandles_unit_SOURCES = \
    test/GetNumHandles_unit.c sysapi/sysapi_util/GetNumHandles.c
test_CopyCommandHeader_unit_CFLAGS = $(CMOCKA_CFLAGS) \
    -I$(srcdir)/include/sapi -I$(srcdir)/sysapi/include/
test_CopyCommandHeader_unit_LDFLAGS = -Wl,--unresolved-symbols=ignore-all
test_CopyCommandHeader_unit_LDADD = $(CMOCKA_LIBS)
test_CopyCommandHeader_unit_SOURCES = \
    test/CopyCommandHeader_unit.c sysapi/sysapi_util/CommandUtil.c \
    sysapi/sysapi/ContextManagement.c sysapi/sysapi_util/changeEndian.c

# how to build stuff
resourcemgr_resourcemgr_CFLAGS   = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS) $(AM_CFLAGS)
resourcemgr_resourcemgr_CXXFLAGS = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS) $(AM_CXXFLAGS)
resourcemgr_resourcemgr_LDADD    = $(libsapi) $(libtcti_device) $(libtcti_socket)
resourcemgr_resourcemgr_LDFLAGS  = $(PTHREAD_LDFLAGS)
resourcemgr_resourcemgr_SOURCES  = $(RESOURCEMGR_C) $(COMMON_SRC)

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
test_tpmclient_tpmclient_CXXFLAGS = $(TPMCLIENT_INC) $(TCTICOMMON_INC) $(TCTIDEVICE_INC) $(AM_CXXFLAGS)
test_tpmclient_tpmclient_LDADD    = $(libsapi) $(libtcti_socket) $(libtcti_device)
test_tpmclient_tpmclient_SOURCES  = $(TPMCLIENT_CXX) $(COMMON_C) $(SAMPLE_C)

test_tpmtest_tpmtest_CFLAGS   = $(TPMTEST_INC) $(AM_CFLAGS)
test_tpmtest_tpmtest_CXXFLAGS = $(TPMTEST_INC) $(AM_CXXFLAGS)
test_tpmtest_tpmtest_LDADD    = $(libsapi) $(libtcti_socket) $(libtcti_device)
test_tpmtest_tpmtest_SOURCES  = $(TPMTEST_CXX) $(COMMON_C) $(SAMPLE_C)

%.pc : %.pc.in
	if [ ! -d $(dir $@) ]; then mkdir -p $(dir $@); fi
	sed -e "s,[@]VERSION[@],$(PACKAGE_VERSION),g; \
	        s,[@]includedir[@],$(includedir),g;" $^ > $@

LIBRARY_LDFLAGS = -fPIC -Wl,--no-undefined

# simple variables
RESOURCEMGR_INC = -I$(srcdir)/include -I$(srcdir)/common \
    -I$(srcdir)/sysapi/include -I$(srcdir)/resourcemgr \
    -I$(srcdir)/test/tpmclient
RESOURCEMGR_C = resourcemgr/resourcemgr.c resourcemgr/criticalsection_linux.c \
    resourcemgr/getcommands.c

TCTICOMMON_INC = -I$(srcdir)/include -I$(srcdir)/common \
    -I$(srcdir)/sysapi/include
TCTICOMMON_C   = tcti/commonchecks.c

TCTIDEVICE_INC = $(TCTICOMMON_INC)
TCTIDEVICE_C   = tcti/tcti_device.c

TCTISOCKET_INC = $(TCTICOMMON_INC)
TCTISOCKET_C   = tcti/platformcommand.c
TCTISOCKET_CXX = tcti/tcti_socket.cpp

TPMCLIENT_INC = -I$(srcdir)/include -I$(srcdir)/sysapi/include \
    -I$(srcdir)/test/tpmclient -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMCLIENT_CXX = test/tpmclient/tpmclient.cpp

TPMTEST_INC = -I$(srcdir)/include -I$(srcdir)/sysapi/include \
    -I$(srcdir)/test/tpmclient -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMTEST_CXX = test/tpmtest/tpmtest.cpp

libsapi = sysapi/libsapi.la
libtcti_device = tcti/libtcti-device.la
libtcti_socket = tcti/libtcti-socket.la
resourcemgr = resourcemgr/resourcemgr
tpmclient   = test/tpmclient/tpmclient
tpmtest     = test/tpmtest/tpmtest
