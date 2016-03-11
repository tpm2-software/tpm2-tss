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

#ifndef RESOURCEMGR_H
#define RESOURCEMGR_H

//#include "tpmclient.h"
#include <tss2/tss2_tcti.h>
#include "sysapi_util.h"
#include <stdlib.h>

#define TSS2_RESMGR_MEMALLOC_FAILED                 ((TSS2_RC)( (1<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_FIND_FAILED                     ((TSS2_RC)( (2<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_BAD_FINDFIELD                   ((TSS2_RC)( (3<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_VIRTUAL_HANDLE_OVERFLOW         ((TSS2_RC)( (4<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))  // If more virtual handles are attempted to be allocated than RM can allocate.
#define TSS2_RESMGR_UNOWNED_HANDLE                  ((TSS2_RC)( (5<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_CONTINUE_BIT_MISMATCH           ((TSS2_RC)( (6<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_INSUFFICIENT_RESPONSE           ((TSS2_RC)( (7<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL)) // TPM response not enough bytes to look at return code.
#define TSS2_RESMGR_INIT_SYS_CONTEXT_FAILED         ((TSS2_RC)( (8<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_INIT_FAILED                     ((TSS2_RC)( (9<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_TCTI_INIT_FAILED                ((TSS2_RC)( (10<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_GAP_HANDLING_FAILED             ((TSS2_RC)( (11<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_UNLOADED_OBJECTS                ((TSS2_RC)( (12<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))
#define TSS2_RESMGR_UNLOADED_SESSIONS               ((TSS2_RC)( (13<<TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT) + TSS2_RESMGR_ERROR_LEVEL))

#ifdef __cplusplus
extern "C" {
#endif

extern UINT32 tpmMaxResponseLen;

extern UINT8 rmDebugPrefix;

TSS2_RC ResourceMgrSendTpmCommand(
    TSS2_TCTI_CONTEXT   *tctiContext,
    size_t              command_size,       /* in */
    uint8_t             *command_buffer     /* in */
);

TSS2_RC ResourceMgrReceiveTpmResponse(
    TSS2_TCTI_CONTEXT   *tctiContext,
    UINT32              *response_size,     /* out */
    uint8_t             *response_buffer,   /* in */
    int32_t             timeout
    );

void ResourceMgrInit( int debugLevel );

// Uncommentting DEBUG_GAP_HANDLING instruments the max active sessions and gap
// max values to something small that allows us to debug this feature.
//
// NOTE:  only uncomment DEBUG_GAP_HANDLING this if you know what
// you're doing.  For this to work a specially doctored simulator
// must be built with the following changes to implementation.h:
//
// #if 0
// #define  MAX_ACTIVE_SESSIONS              64
// #define  CONTEXT_SLOT                     UINT16
// #else
// #define  MAX_ACTIVE_SESSIONS              32
// #define  CONTEXT_SLOT                     UINT8
// #endif
//
// #define DEBUG_GAP_HANDLING

//
#ifdef DEBUG_GAP_HANDLING
// NOTE: these values must match the ones
// for the simulator.  For the following
// I was running against a simulator built with
// modified values for these.  This was
// done to facillitate faster testing of gap
// handling in the resource manager.
#define DEBUG_MAX_ACTIVE_SESSIONS   32
#define DEBUG_GAP_MAX   255
#endif

TSS2_RC InitResMgr( int debugLevel );

#ifdef __cplusplus
}
#endif


extern void *(*rmMalloc)(size_t size);
extern void (*rmFree)(void *entry);

extern int printRMTables;

#endif

