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

SAMPLE_SRC = \
    ../common/sample/CatSizedByteBuffer.c \
    ../common/sample/CopySizedBuffer.c \
    ../common/sample/CreateNullSession.c \
    ../common/sample/DecryptEncrypt.c \
    ../common/sample/Entity.c \
    ../common/sample/kdfa.c \
    ../common/sample/LoadExternalHMACKey.c \
    ../common/sample/sample.h \
    ../common/sample/SessionHmac.c \
    ../common/sample/SetLocality.c \
    ../common/sample/StartAuthSession.c \
    ../common/sample/TpmCalcPHash.c \
    ../common/sample/TpmHandleToName.c \
    ../common/sample/TpmHash.c \
    ../common/sample/TpmHmac.c \
    ../common/sample/sample.h
TPMSOCKETS_SRC = \
    ../../tcti/tpmsockets/tpmsockets.cpp \
    ../../tcti/tpmsockets/tpmsockets.h
SYSAPI_SRC = \
    ../../sysapi/include/basetypes.h \
    ../../sysapi/include/endianConv.h \
    ../../sysapi/include/implementation.h \
    ../../sysapi/include/tpm20.h \
    ../../sysapi/include/tpmb.h \
    ../../sysapi/include/tss2_common.h \
    ../../sysapi/include/tss2_sys_api_marshalUnmarshal.h \
    ../../sysapi/include/tss2_sys_api_part3.h \
    ../../sysapi/include/tss2_sysapi_util.h \
    ../../sysapi/include/tss2_sys.h \
    ../../sysapi/include/tss2_tcti.h \
    ../../sysapi/include/tss2_tcti_util.h \
    ../../sysapi/include/tss2_tpm2_types.h

TPMCLIENT_SRC = \
    tpmclient.cpp \
    tpmclient.h \
    $(SAMPLE_SRC) \
    $(SYSAPI_SRC)

INCLUDE_DIRS = -I$(srcdir)/../../sysapi/include -I$(srcdir) \
    -I$(srcdir)/../../tcti/tpmsockets -I$(srcdir)/../../common \
    -I$(srcdir)/../common/sample -I$(srcdir)/../../resourcemgr

AM_CFLAGS = $(INCLUDE_DIRS)
AM_CXXFLAGS = $(INCLUDE_DIRS)

LIBTPM = ../../sysapi/libtpm.a
LIBCMN = ../../common/libcommon.a

$(LIBCMN):
	$(MAKE) -C ../../common
$(LIBTPM):
	$(MAKE) -C ../../sysapi

noinst_PROGRAMS = tpmclient
LDADD = sapiclient_tpmsockets.o sapiclient_getcommands.o $(LIBCMN) $(LIBTPM)
tpmclient_SOURCES = $(TPMCLIENT_SRC)

# Build special version of tpmsockets code for test application.
sapiclient_getcommands.o: AM_CFLAGS+=-DSAPI_CLIENT
sapiclient_getcommands.o: ../../common/getcommands.c
	$(CC) $(AM_CFLAGS) -c $< -o $@

# Build special version of getcommands code for test application.
sapiclient_tpmsockets.o: AM_CXXFLAGS+=-DSAPI_CLIENT
sapiclient_tpmsockets.o: ../../tcti/tpmsockets/tpmsockets.cpp
	$(CXX) $(AM_CXXFLAGS) -c $< -o $@


