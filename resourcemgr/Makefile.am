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

RESOURCEMGR_SRC = resourcemgr.c resourcemgr.h
TPMSOCKETS_SRC = ../tcti/tpmsockets/tpmsockets.cpp \
    ../tcti/tpmsockets/tpmsockets.h
LOCALTPM_SRC = ../tcti/localtpm/localtpm.c ../tcti/localtpm/localtpm.h
SYSAPI_INC = \
    ../sysapi/include/tss2_tpm2_types.h \
    ../sysapi/include/tss2_sys_api_part3.h \
    ../sysapi/include/tss2_tcti.h \
    ../sysapi/include/basetypes.h \
    ../sysapi/include/tss2_tcti_util.h \
    ../sysapi/include/tpm20.h \
    ../sysapi/include/tss2_sysapi_util.h \
    ../sysapi/include/implementation.h \
    ../sysapi/include/tss2_common.h \
    ../sysapi/include/endianConv.h \
    ../sysapi/include/tss2_sys_api_marshalUnmarshal.h \
    ../sysapi/include/tss2_sys.h \
    ../syspai/include/tpmb.h

INCLUDE_DIRS = -I$(srcdir)/../sysapi/include -I$(srcdir)/../common \
    -I$(srcdir)/../tcti/tpmsockets -I$(srcdir)/../tcti/localtpm -I$(srcdir) \
    -I$(srcdir)/../test/tpmclient

AM_CFLAGS = $(INCLUDE_DIRS)
AM_CXXFLAGS = $(INCLUDE_DIRS)

LIBTPM = ../sysapi/libtpm.a
LIBCMN = ../common/libcommon.a
LIBS = -lpthread

$(LIBCMN):
	$(MAKE) -C ../common
$(LIBTPM):
	$(MAKE) -C ../sysapi

bin_PROGRAMS = resourcemgr
resourcemgr_LDADD = $(LIBCMN) $(LIBTPM)
resourcemgr_SOURCES = $(RESOURCEMGR_SRC) $(TPMSOCKETS_SRC) $(LOCALTPM_SRC) \
     $(COMMON_SRC) $(SYSAPI_INC)
