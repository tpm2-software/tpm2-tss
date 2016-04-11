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
#include <tcti/tcti_socket.h>
#include <stdio.h>
#include "sockets.h"

#ifdef __cplusplus
extern "C" {
#endif

enum debugLevel { DBG_NO_COMMAND = 0, DBG_COMMAND = 1, DBG_COMMAND_RM = 2, DBG_COMMAND_RM_TABLES = 3 };

int DebugPrintfCallback( void *data, printf_type type, const char *format, ...);
int DebugPrintf( printf_type type, const char *format, ...);
void DebugPrintBuffer( printf_type type, UINT8 *command_buffer, UINT32 cnt1 );
int DebugPrintBufferCallback( void *data, printf_type type, UINT8 *buffer, UINT32 length );
const char* strTpmCommandCode( TPM_CC code );

#ifdef DEBUG
#define DEBUG_PRINT_BUFFER( type, buffer, length )  DebugPrintBuffer( type, buffer, length )
#else
#define DEBUG_PRINT_BUFFER( type, buffer, length )
#endif

#ifdef __cplusplus
}
#endif

#endif
