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

TOOLS_PATH=$(TSSTOOLS_PATH)\VC\BIN
PATH=$(TSSTOOLS_PATH)\Common7\IDE\;$(PATH)

#
# Build tools. Needs localization
#
ML_PATH      = $(TOOLS_PATH)
CL_PATH      = $(TOOLS_PATH)
LINK_PATH    = $(TOOLS_PATH)
LIB_PATH     = $(TOOLS_PATH)
NMAKE_PATH   = $(TOOLS_PATH)
DUMPBIN_PATH = $(TOOLS_PATH)

ML64_PATH    = $(TOOLS64_PATH)
CL64_PATH    = $(TOOLS64_PATH)
LINK64_PATH  = $(TOOLS64_PATH)
LIB64_PATH   = $(TOOLS64_PATH)


ML                   = $(ML_PATH)\ml
CL                   = $(CL_PATH)\cl
LINK                 = $(LINK_PATH)\link
LIB                  = $(LIB_PATH)\lib
NMAKE                = $(NMAKE_PATH)\nmake

ML64                 = $(ML64_PATH)\ml64
CL64                 = $(CL64_PATH)\cl
LINK64               = $(LINK64_PATH)\link
LIB64                = $(LIB64_PATH)\lib

ML_FLAGS             = /Gd /c /Cx /Wall /WX /Zi /coff /Fo$@ $(ALL_INCLUDES) /D__ASM__=1
ML64_FLAGS           = /c /Cx /Wall /WX /Fo$@ $(ALL_INCLUDES) /Zi /D__ASM__=1

CL_FLAGS_RELEASE     = /c /WX /W3 /Zp1 /O1 $(ALL_INCLUDES)
CL_FLAGS_DEBUG       = /c /GS- /WX /W3 /Zp1 /Zi /Od /Fd$(@R).pdb $(ALL_INCLUDES)
CL64_FLAGS           = $(CL_FLAGS)

LNK_FLAGS            = /DYNAMICBASE \
                       /MERGE:ADATA32=EDATA32 \
                       /MERGE:SDATA32=EDATA32 \
                       /MERGE:CODE32=.text \
                       /MERGE:.rdata=.text \
                       /MERGE:.data=.text \
                       /base:0 \
                       -LAST:EDATA32 -LAST:.text \
                       /OPT:REF /OUT:$(BLD_DIR)\$(TSS_NAME).exe \
                       /PDB:$(BLD_DIR)\$(TSS_NAME).pdb \
                       /NODEFAULTLIB /ALIGN:16 /IGNORE:4108 /IGNORE:4254 \
                       /MAP /DEBUG /ENTRY:$(TSS_ENTRYPOINT) \
                       /SUBSYSTEM:native /LIBPATH:$(LIB_DIR) \

LNK64_FLAGS          = /DYNAMICBASE \
                       /MERGE:.rdata=.text \
                       /base:0 \
                       -LAST:.text -LAST:.pdata\
                       /OPT:REF /OPT:ICF /OUT:$(BLD_DIR)\$(TSS64_NAME).exe \
                       /PDB:$(BLD_DIR)\$(TSS64_NAME).pdb \
                       /NODEFAULTLIB /IGNORE:4108 /IGNORE:4254 \
                       /MAP /DEBUG /ENTRY:$(TSS64_ENTRYPOINT) \
                       /SUBSYSTEM:native /LIBPATH:$(LIB_DIR) \

LIB_FLAGS            = /NOLOGO
LIB64_FLAGS          = $(LIB_FLAGS)

#
# Directories.
# Four directories come from batch files:
# TSS_ROOT_DIR, TOOLS_PATH, and TOOLS64_PATH come from ROOT.BAT located in the
# root of the TSS tree.
# PROJECT_DIR  comes from build batch file located in the project tip
# Others are defined here.
#

#
# Suffixes
#

.SUFFIXES :
.SUFFIXES : .exe .obj .c .asm .equ .inc .h


BASE_DIR                        = .
LIBRARY_DIR			= .\lib
BLD_DIR                         = build
INCLUDE_DIR                     = ..\include
ALL_INCLUDES         = /I$(INCLUDE_DIR) /I$(TSSTOOLS_PATH)\VC\include /I$(BASE_DIR)\include
LIBRARY                         = tpm.lib


#
# These are the directories whose C files will be built.
#
LOCAL_DIRS      = sysapi sysapi_util 

!if "$(TASK)"=="BUILD"
!include $(BLD_DIR)\tpm_objects.tmp
!include $(BLD_DIR)\tpm_depends.tmp
!endif

!if "$(TYPE)"=="DEBUG"
CL_FLAGS = $(CL_FLAGS_DEBUG)
LIB_DIR = $(LIBRARY_DIR)\debug
!endif

!if "$(TYPE)"=="RELEASE"
CL_FLAGS = $(CL_FLAGS_RELEASE)
LIB_DIR = $(LIBRARY_DIR)\release
!endif

# 
# NMAKER evaluates targets in the order in which they appear in make file, not in
# order in which they are listed in dependency line of ALL target.
# 

all: Debug Release

Debug: $(LIB_DIR)\$(LIBRARY)
        $(MAKE) /F windows.mak TYPE=DEBUG init_build
        $(MAKE) /F windows.mak TYPE=DEBUG TASK=BUILD all_build

Release: $(LIB_DIR)\$(LIBRARY)
        $(MAKE) /F windows.mak TYPE=RELEASE init_build
        $(MAKE) /F windows.mak TYPE=RELEASE TASK=BUILD all_build

init_build:
        ECHO ***** $(CL_FLAGS)  ******
        @echo ===== Performing local INIT_BUILD step =====
        - md $(BLD_DIR)
        - md $(LIB_DIR)
        @echo > nul <<.\tpm_dirs.tmp        
$(LOCAL_DIRS: = ^
)        
<<
        @echo OBJECTS= \> $(BLD_DIR)\tpm_objects.tmp
        -for /F %i IN (tpm_dirs.tmp) DO for /F "usebackq" %j IN (`dir /B %i\*.c*`) DO @echo. $(LIB_DIR)\%~nj.obj \>> $(BLD_DIR)\tpm_objects.tmp
        -for /F %i IN (tpm_dirs.tmp) DO for /F "usebackq" %j IN (`dir /B %i\*.asm`) DO @echo. $(LIB_DIR)\%~nj.obj \>> $(BLD_DIR)\tpm_objects.tmp
        @echo.>$(BLD_DIR)\tpm_depends.tmp
        @echo ALL_DEPS= \> $(BLD_DIR)\tpm_depends.tmp
        @for /F "usebackq" %i IN (`dir /B $(INCLUDE_DIR)`) DO @echo. $(INCLUDE_DIR)\%i \>> $(BLD_DIR)\tpm_depends.tmp
        @echo.  >> $(BLD_DIR)\tpm_depends.tmp

        -for /F %i IN (tpm_dirs.tmp) DO for /F "usebackq" %j IN (`dir /B %i\*.c*`) DO @echo.$(LIB_DIR)\%~nj.obj: $(BASE_DIR)\%i\%j $$(ALL_DEPS) >> $(BLD_DIR)\tpm_depends.tmp && @echo.  $$(CL) $(CL_FLAGS) /Fo$$^@ $(BASE_DIR)\%i\%j >> $(BLD_DIR)\tpm_depends.tmp && @echo. >> $(BLD_DIR)\tpm_depends.tmp
#        -for /F %i IN (tpm_dirs.tmp) DO for /F "usebackq" %j IN (`dir /B %i\*.asm`) DO @echo. $(LIB_DIR)\%~nj.obj \>> $(BLD_DIR)\tpm_objects.tmp

#        @for /F %i IN (tpm_dirs.tmp) DO @echo.{$$(BASE_DIR)\%i}.c{$$(LIB_DIR)}.obj: >> $(BLD_DIR)\tpm_depends.tmp && @echo.  $$(CL) $$(CL_FLAGS) $$(TPM_CL_FLAGS) /Fo$$^@ $$^< >> $(BLD_DIR)\tpm_depends.tmp && @echo. >> $(BLD_DIR)\tpm_depends.tmp
#        @for /F %i IN (tpm_dirs.tmp) DO @echo.{$$(BASE_DIR)\%i}.asm{$$(LIB_DIR)}.obj: >> $(BLD_DIR)\tpm_depends.tmp && @echo.  $$(ML) $$(ML_FLAGS) /Fo$$^@ $$^< >> $(BLD_DIR)\tpm_depends.tmp && @echo. >> $(BLD_DIR)\tpm_depends.tmp

$(LIB_DIR)\$(LIBRARY):  $(OBJECTS)
        $(LIB) $(LIB_FLAGS) /OUT:$(LIB_DIR)\$(LIBRARY) $(OBJECTS)

all_build: $(OBJECTS) $(ALL_DEPS) $(LIB_DIR)\$(LIBRARY)
        ECHO ^^^^ $(CL_FLAGS)  ^^^^
        ECHO ^^^^ $(LIB_DIR)\$(LIBRARY)  ^^^^
        @echo ===== Performing local ALL_BUILD step =====

clean: 
        @echo ===== Performing local CLEAN step =====
        - rd /S /Q build
        - rd /S /Q lib

