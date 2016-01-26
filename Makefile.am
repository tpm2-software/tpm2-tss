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
lib_LTLIBRARIES = $(libtpm2sapi) $(libtpm2tctidev) $(libtpm2tctisock)

# headers and where to install them
libtpm2sapidir      = $(includedir)/tpm2sapi
libtpm2sapi_HEADERS = $(srcdir)/include/tpm2sapi/*.h
libtpm2tctidir      = $(includedir)/tpm2tcti
libtpm2tcti_HEADERS = $(srcdir)/include/tpm2tcti/*.h

# how to build stuff
resourcemgr_resourcemgr_CFLAGS   = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_CXXFLAGS = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_LDADD    = $(libtpm2sapi) 
resourcemgr_resourcemgr_LDFLAGS  = $(PTHREAD_LDFLAGS)
resourcemgr_resourcemgr_SOURCES  = $(RESOURCEMGR_C) $(TPMSOCKETS_C) $(TPMSOCKETS_CXX) \
    $(COMMON_C) $(COMMONTCTI_C) $(LOCALTPM_C)

sysapi_libtpm2sapi_la_CFLAGS  = -I$(srcdir)/include/tpm2sapi
sysapi_libtpm2sapi_la_SOURCES = $(SYSAPI_C) $(SYSAPIUTIL_C)

tcti_libtpm2tctidev_la_CFLAGS   = -DSAPI_CLIENT $(TCTIDEV_INC)
tcti_libtpm2tctidev_la_SOURCES  = common/debug.c $(LOCALTPM_C) $(COMMONTCTI_C)

tcti_libtpm2tctisock_la_CFLAGS   = -DSAPI_CLIENT $(TCTISOCK_INC)
tcti_libtpm2tctisock_la_CXXFLAGS = -DSAPI_CLIENT $(TCTISOCK_INC)
tcti_libtpm2tctisock_la_SOURCES  = common/debug.c $(TPMSOCKETS_C) $(TPMSOCKETS_CXX) $(COMMONTCTI_C)

test_tpmclient_tpmclient_CFLAGS   = -DSAPI_CLIENT $(TPMCLIENT_INC)
test_tpmclient_tpmclient_CXXFLAGS = -DSAPI_CLIENT $(TPMCLIENT_INC) $(COMMONTCTI_INC) $(TCTIDEV_INC)
test_tpmclient_tpmclient_LDADD    = $(libtpm2sapi) $(libtpm2tctisock) $(libtpm2tctidev)
test_tpmclient_tpmclient_SOURCES  = $(TPMCLIENT_CXX) $(COMMON_C) $(SAMPLE_C)

test_tpmtest_tpmtest_CFLAGS   = -DSAPI_CLIENT $(TPMTEST_INC)
test_tpmtest_tpmtest_CXXFLAGS = -DSAPI_CLIENT $(TPMTEST_INC)
test_tpmtest_tpmtest_LDADD    = $(libtpm2sapi) $(libtpm2tctisock)
test_tpmtest_tpmtest_SOURCES  = $(TPMTEST_CXX) $(COMMON_C) $(SAMPLE_C)

# simple variables
RESOURCEMGR_INC = -I$(srcdir)/include/tpm2sapi -I$(srcdir)/common \
    -I$(srcdir)/include/tpm2tcti \
    -I$(srcdir)/resourcemgr -I$(srcdir)/test/tpmclient \
    -I$(srcdir)/tcti/commonTcti
RESOURCEMGR_C = resourcemgr/resourcemgr.c

COMMONTCTI_INC = -I$(srcdir)/include/tpm2sapi -I$(srcdir)/common \
    -I$(srcdir)/include/tpm2tcti -I$(srcdir)/tcti/commonTcti

TCTIDEV_INC = -I$(srcdir)/tcti/localtpm $(COMMONTCTI_INC)

TCTISOCK_INC = -I$(srcdir)/tcti/tpmsockets $(COMMONTCTI_INC)

TPMCLIENT_INC = -I$(srcdir)/include/tpm2sapi -I$(srcdir)/include/tpm2tcti \
    -I$(srcdir)/test/tpmclient -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMCLIENT_CXX = test/tpmclient/tpmclient.cpp

TPMTEST_INC = -I$(srcdir)/include/tpm2sapi -I$(srcdir)/include/tpm2tcti \
    -I$(srcdir)/test/tpmclient -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMTEST_CXX = test/tpmtest/tpmtest.cpp

libtpm2sapi = sysapi/libtpm2sapi.la
libtpm2tctidev = tcti/libtpm2tctidev.la
libtpm2tctisock = tcti/libtpm2tctisock.la
resourcemgr = resourcemgr/resourcemgr
tpmclient   = test/tpmclient/tpmclient
tpmtest     = test/tpmtest/tpmtest
