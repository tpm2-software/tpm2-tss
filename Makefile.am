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
AM_CFLAGS = -I$(srcdir)/include
AM_CPPFLAGS = -I$(srcdir)/include

# stuff to build, what that stuff is, and where/if to install said stuff
sbin_PROGRAMS   = $(resourcemgr)
noinst_PROGRAMS = $(tpmclient) $(tpmtest)
lib_LTLIBRARIES = $(libtss2) $(libtctidevice) $(libtctisocket)
# unit tests
check_PROGRAMS  = test/tcti_device
TESTS = $(check_PROGRAMS)

# headers and where to install them
libtss2dir      = $(includedir)/tss2
libtss2_HEADERS = $(srcdir)/include/tss2/*.h
libtctidir      = $(includedir)/tcti
libtcti_HEADERS = $(srcdir)/include/tcti/*.h

test_tcti_device_CFLAGS  = $(CMOCKA_CFLAGS) -I$(srcdir) -I$(srcdir)/sysapi/include
test_tcti_device_LDADD   = $(libtss2) $(libtctidevice) $(CMOCKA_LIBS)
test_tcti_device_SOURCES = test/tcti_device.c test/tcti_device_test.c

# how to build stuff
resourcemgr_resourcemgr_CFLAGS   = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_CXXFLAGS = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_LDADD    = $(libtss2)
resourcemgr_resourcemgr_LDFLAGS  = $(PTHREAD_LDFLAGS)
resourcemgr_resourcemgr_SOURCES  = $(RESOURCEMGR_C) $(TCTISOCKET_C) \
    $(TCTISOCKET_CXX) $(COMMON_C) $(TCTICOMMON_C) $(TCTIDEVICE_C) \
    common/sockets.cpp

sysapi_libtss2_la_CFLAGS  = -I$(srcdir)/include -I$(srcdir)/sysapi/include
sysapi_libtss2_la_LDFLAGS = $(LIBRARY_LDFLAGS)
sysapi_libtss2_la_SOURCES = $(SYSAPI_C) $(SYSAPIUTIL_C)

tcti_libtctidevice_la_CFLAGS   = $(TCTIDEVICE_INC)
tcti_libtctidevice_la_LDFLAGS  = $(LIBRARY_LDFLAGS)
tcti_libtctidevice_la_SOURCES  = common/debug.c $(TCTIDEVICE_C) \
    sysapi/sysapi_util/changeEndian.c $(TCTICOMMON_C)

tcti_libtctisocket_la_CFLAGS   = -DSAPI_CLIENT $(TCTISOCKET_INC)
tcti_libtctisocket_la_CXXFLAGS = -DSAPI_CLIENT $(TCTISOCKET_INC)
tcti_libtctisocket_la_LDFLAGS  = $(LIBRARY_LDFLAGS)
tcti_libtctisocket_la_SOURCES  =  common/debug.c $(TCTISOCKET_C) \
    sysapi/sysapi_util/changeEndian.c $(TCTISOCKET_CXX) $(TCTICOMMON_C) \
    common/sockets.cpp

test_tpmclient_tpmclient_CFLAGS   = -DSAPI_CLIENT $(TPMCLIENT_INC)
test_tpmclient_tpmclient_CXXFLAGS = -DSAPI_CLIENT $(TPMCLIENT_INC) $(TCTICOMMON_INC) $(TCTIDEVICE_INC)
test_tpmclient_tpmclient_LDADD    = $(libtss2) $(libtctisocket) $(libtctidevice)
test_tpmclient_tpmclient_SOURCES  = $(TPMCLIENT_CXX) $(COMMON_C) $(SAMPLE_C)

test_tpmtest_tpmtest_CFLAGS   = -DSAPI_CLIENT $(TPMTEST_INC)
test_tpmtest_tpmtest_CXXFLAGS = -DSAPI_CLIENT $(TPMTEST_INC)
test_tpmtest_tpmtest_LDADD    = $(libtss2) $(libtctisocket) $(libtctidevice)
test_tpmtest_tpmtest_SOURCES  = $(TPMTEST_CXX) $(COMMON_C) $(SAMPLE_C)

LIBRARY_LDFLAGS = -fPIC

# simple variables
RESOURCEMGR_INC = -I$(srcdir)/include -I$(srcdir)/common \
    -I$(srcdir)/sysapi/include -I$(srcdir)/resourcemgr \
    -I$(srcdir)/test/tpmclient
RESOURCEMGR_C = resourcemgr/resourcemgr.c

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

libtss2 = sysapi/libtss2.la
libtctidevice = tcti/libtctidevice.la
libtctisocket = tcti/libtctisocket.la
resourcemgr = resourcemgr/resourcemgr
tpmclient   = test/tpmclient/tpmclient
tpmtest     = test/tpmtest/tpmtest
