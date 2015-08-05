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

RESOURCE_MGR_HEADERS := $(shell ls ../resourcemgr/*.h )
SAMPLE_OBJS := $(shell ls ../common/sample/*.c | sed 's/\.\.\/common\/sample/$(TARGET_TYPE)/' | sed 's/\.c$$/\.o /' )
SAMPLE_HEADERS := $(shell ls ../common/sample/*.h )
#TPMSOCKETS_OBJS := $(shell ls ../../tcti/tpmsockets/*.cpp | sed 's/\.\.\/\.\.\/tpmsockets/$(TARGET_TYPE)/' | sed 's/\.cpp$$/\.o /' )
TPMSOCKETS_HEADERS := $(shell ls ../../tcti/tpmsockets/*.h )
COMMON_OBJS := $(shell ls ../../common/*.c | sed 's/\.\.\/\.\.\/common/$(TARGET_TYPE)/' | sed 's/\.c$$/\.o /' )
COMMON_HEADERS := $(shell ls ../../common/*.h )
SYSAPI_HEADERS := $(shell ls ../../sysapi/include/*.h )

TPMCLIENT_HEADERS = tpmclient.h $(SAMPLE_HEADERS) $(TPMSOCKETS_HEADERS) $(COMMON_HEADERS) $(SYSAPI_HEADERS)


CC = gcc
CPLUS = g++

debug_CFLAGS = -O0 -ggdb3 -Wall -Werror
release_CFLAGS = -Os -Wall -Werror
debug_CPLUSFLAGS = -O0 -ggdb3 -fno-operator-names -fpermissive -Wall -Werror
release_CPLUSFLAGS = -Os -fno-operator-names -fpermissive -Wall -Werror

CFLAGS = $($(TARGET_TYPE)_CFLAGS)
CPLUSFLAGS = $($(TARGET_TYPE)_CPLUSFLAGS)

INCLUDE_DIRS = -I../../sysapi/include -I. -I../../tcti/tpmsockets -I../../common -I../common/sample -I../../resourcemgr
LIBS = ../../sysapi/lib/$(TARGET_TYPE)/libtpm.a

OBJS = $(SYSCONTEXT_OBJS) $(SAMPLE_OBJS) $(TARGET_TYPE)/sapiclient_tpmsockets.o $(COMMON_OBJS) 

.PHONY: tpmlib_debug tpmlib_release DIRS all debug release 

all:  debug release 

debug: tpmlib_debug
	$(MAKE) -f Makefile debug/tpmclient TARGET_TYPE=debug

release: tpmlib_release
	$(MAKE) -f Makefile release/tpmclient TARGET_TYPE=release

DIRS:
	-@mkdir $(TARGET_TYPE) 2> /dev/null

tpmlib_debug: 
	@$(MAKE) -C ../../sysapi -f Makefile debug

tpmlib_release: 
	@$(MAKE) -C ../../sysapi -f Makefile release

$(TARGET_TYPE)/tpmclient: DIRS $(TARGET_TYPE)/tpmclient.o $(OBJS) $(LIBS) Makefile 
	$(CPLUS) $(CPLUSFLAGS) $(INCLUDE_DIRS) -o $(@D)/tpmclient $(@D)/tpmclient.o $(OBJS) $(LIBS)

$(TARGET_TYPE)/%.o: %.cpp $(TPMCLIENT_HEADERS) Makefile
	$(CPLUS) $(CFLAGS) $(INCLUDE_DIRS) -c $< -o $@

$(TARGET_TYPE)/%.o: ../common/sample/%.c $(COMMON_HEADERS) Makefile $(SYSAPI_HEADERS) $(SAMPLE_HEADERS) 
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -c $< -o $@

# Build special version of tpmsockets code for test application.
$(TARGET_TYPE)/sapiclient_tpmsockets.o: ../../tcti/tpmsockets/*.cpp # $(TPMSOCKETS_HEADERS) Makefile $(SYSAPI_HEADERS) $(COMMON_HEADERS) 
	$(CPLUS) -DSAPI_CLIENT $(CPLUSFLAGS) $(INCLUDE_DIRS) -c $< -o $@

$(TARGET_TYPE)/%.o: ../../common/%.c $(COMMON_HEADERS) Makefile $(SYSAPI_HEADERS) $(COMMON_HEADERS) 
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -c $< -o $@

clean:
	@rm -f tpmclient resourcemgr 
	@rm debug -rf
	@rm release -rf
	@$(MAKE) -C ../../sysapi -f Makefile clean
