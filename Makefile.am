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

# stuff to build, what that stuff is, and where/if to install said stuff
sbin_PROGRAMS   = $(resourcemgr)
noinst_PROGRAMS = $(tpmclient) $(tpmtest)
lib_LTLIBRARIES = $(libtss2) $(libtctidev) $(libtctisock)

# headers and where to install them
libtss2dir      = $(includedir)/tss2
libtss2_HEADERS = $(srcdir)/include/tss2/*.h
libtctidir      = $(includedir)/tcti
libtcti_HEADERS = $(srcdir)/include/tcti/*.h

# how to build stuff
resourcemgr_resourcemgr_CFLAGS   = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_CXXFLAGS = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_LDADD    = $(libtss2)
resourcemgr_resourcemgr_LDFLAGS  = $(PTHREAD_LDFLAGS)
resourcemgr_resourcemgr_SOURCES  = $(RESOURCEMGR_C) $(TPMSOCKETS_CXX) \
    $(COMMON_C) $(COMMONTCTI_C) $(LOCALTPM_C)

sysapi_libtss2_la_CFLAGS  = -I$(srcdir)/include -I$(srcdir)/sysapi/include
sysapi_libtss2_la_SOURCES = $(SYSAPI_C) $(SYSAPIUTIL_C)

tcti_libtctidev_la_CFLAGS   = -DSAPI_CLIENT $(TCTIDEV_INC)
tcti_libtctidev_la_SOURCES  = common/debug.c \
    sysapi/sysapi_util/changeEndian.c $(LOCALTPM_C) $(COMMONTCTI_C)

tcti_libtctisock_la_CFLAGS   = -DSAPI_CLIENT $(TCTISOCK_INC)
tcti_libtctisock_la_CXXFLAGS = -DSAPI_CLIENT $(TCTISOCK_INC)
tcti_libtctisock_la_SOURCES  = common/debug.c \
    sysapi/sysapi_util/changeEndian.c $(TPMSOCKETS_CXX) $(COMMONTCTI_C)

test_tpmclient_tpmclient_CFLAGS   = -DSAPI_CLIENT $(TPMCLIENT_INC)
test_tpmclient_tpmclient_CXXFLAGS = -DSAPI_CLIENT $(TPMCLIENT_INC) $(COMMONTCTI_INC) $(TCTIDEV_INC)
test_tpmclient_tpmclient_LDADD    = $(libtss2) $(libtctisock) $(libtctidev)
test_tpmclient_tpmclient_SOURCES  = $(TPMCLIENT_CXX) $(COMMON_C) $(SAMPLE_C)

test_tpmtest_tpmtest_CFLAGS   = -DSAPI_CLIENT $(TPMTEST_INC)
test_tpmtest_tpmtest_CXXFLAGS = -DSAPI_CLIENT $(TPMTEST_INC)
test_tpmtest_tpmtest_LDADD    = $(libtss2) $(libtctisock)
test_tpmtest_tpmtest_SOURCES  = $(TPMTEST_CXX) $(COMMON_C) $(SAMPLE_C)

# simple variables
RESOURCEMGR_INC = -I$(srcdir)/include -I$(srcdir)/common \
    -I$(srcdir)/sysapi/include \
    -I$(srcdir)/resourcemgr -I$(srcdir)/test/tpmclient \
    -I$(srcdir)/tcti/commonTcti
RESOURCEMGR_C = resourcemgr/resourcemgr.c

COMMONTCTI_INC = -I$(srcdir)/include -I$(srcdir)/common \
    -I$(srcdir)/tcti/commonTcti -I$(srcdir)/sysapi/include

TCTIDEV_INC = -I$(srcdir)/tcti/localtpm $(COMMONTCTI_INC)

TCTISOCK_INC = -I$(srcdir)/tcti/tpmsockets $(COMMONTCTI_INC)

TPMCLIENT_INC = -I$(srcdir)/include -I$(srcdir)/sysapi/include \
    -I$(srcdir)/test/tpmclient -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMCLIENT_CXX = test/tpmclient/tpmclient.cpp

TPMTEST_INC = -I$(srcdir)/include -I$(srcdir)/sysapi/include \
    -I$(srcdir)/test/tpmclient -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMTEST_CXX = test/tpmtest/tpmtest.cpp

libtss2 = sysapi/libtss2.la
libtctidev = tcti/libtctidev.la
libtctisock = tcti/libtctisock.la
resourcemgr = resourcemgr/resourcemgr
tpmclient   = test/tpmclient/tpmclient
tpmtest     = test/tpmtest/tpmtest
