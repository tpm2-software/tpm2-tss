//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#ifndef DEBUG_H
#define DEBUG_H

#include <tss2/tpm20.h>
#include <stdio.h>
#include "sockets.h"

#ifdef __cplusplus
extern "C" {
#endif

enum debugLevel { DBG_NO_COMMAND = 0, DBG_COMMAND = 1, DBG_COMMAND_RM = 2, DBG_COMMAND_RM_TABLES = 3 };

void PrintRMDebugPrefix();

int DebugPrintf( UINT8 type, const char *format, ...);
void DebugPrintBuffer( UINT8 *command_buffer, UINT32 cnt1 );

void DebugPrintBufferOpen( UINT8 *buffer, UINT32 length );

extern int (*printfFunction)( UINT8 type, const char *format, ...);

enum printf_types { NO_PREFIX = 0, RM_PREFIX = 1 };

extern UINT8 rmDebugPrefix;

#ifdef DEBUG
#define DEBUG_PRINT_BUFFER( buffer, length )  DebugPrintBuffer( buffer, length )
#else
#define DEBUG_PRINT_BUFFER( buffer, length )
#endif

#ifdef __cplusplus
}
#endif

#endif
