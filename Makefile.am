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

bin_PROGRAMS = resourcemgr/resourcemgr test/tpmclient/tpmclient test/tpmtest/tpmtest
noinst_LIBRARIES = sysapi/libtpm.a

resourcemgr_resourcemgr_CFLAGS   = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_CXXFLAGS = $(RESOURCEMGR_INC) $(PTHREAD_CFLAGS)
resourcemgr_resourcemgr_LDADD    = $(noinst_LIBRARIES)
resourcemgr_resourcemgr_LDFLAGS  = $(PTHREAD_LDFLAGS)
resourcemgr_resourcemgr_SOURCES  = $(RESOURCEMGR_SRC) $(TPMSOCKETS_SRC) \
     $(LOCALTPM_SRC) $(COMMON_SRC)

sysapi_libtpm_a_CFLAGS  = -I$(srcdir)/sysapi/include/
sysapi_libtpm_a_SOURCES = $(SYSAPI_SRC) $(SYSAPIUTIL_SRC) $(SYSAPI_INC)

test_tpmclient_tpmclient_CFLAGS   = -DSAPI_CLIENT $(TPMCLIENT_INC)
test_tpmclient_tpmclient_CXXFLAGS = -DSAPI_CLIENT $(TPMCLIENT_INC)
test_tpmclient_tpmclient_LDADD    = $(noinst_LIBRARIES)
test_tpmclient_tpmclient_SOURCES  = $(COMMON_SRC) $(SAMPLE_SRC) \
    $(TPMCLIENT_SRC) $(TPMSOCKETS_SRC)

test_tpmtest_tpmtest_CFLAGS   = -DSAPI_CLIENT $(TPMTEST_INC)
test_tpmtest_tpmtest_CXXFLAGS = -DSAPI_CLIENT $(TPMTEST_INC)
test_tpmtest_tpmtest_LDADD    = $(noinst_LIBRARIES)
test_tpmtest_tpmtest_SOURCES  = $(COMMON_SRC) $(SAMPLE_SRC) \
    $(TPMTEST_SRC) $(TPMSOCKETS_SRC)

RESOURCEMGR_INC = -I$(srcdir)/sysapi/include -I$(srcdir)/common \
    -I$(srcdir)/tcti/tpmsockets -I$(srcdir)/tcti/localtpm \
    -I$(srcdir)/resourcemgr -I$(srcdir)/test/tpmclient
RESOURCEMGR_SRC = resourcemgr/resourcemgr.c resourcemgr/resourcemgr.h

TPMCLIENT_INC = -I$(srcdir)/sysapi/include -I$(srcdir)/test/tpmclient \
    -I$(srcdir)/tcti/tpmsockets -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMCLIENT_SRC = test/tpmclient/tpmclient.cpp test/tpmclient/tpmclient.h

TPMTEST_INC = -I$(srcdir)/sysapi/include -I$(srcdir)/test/tpmclient \
    -I$(srcdir)/tcti/tpmsockets -I$(srcdir)/common \
    -I$(srcdir)/test/common/sample -I$(srcdir)/resourcemgr
TPMTEST_SRC = test/tpmtest/tpmtest.cpp
