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

#ifdef  _WIN32

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include <tpm20.h>
#include "localtbs.h"

#include <tss2_sysapi_util.h>
#include "debug.h"

#include <Tbs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TBS_RESULT_BUFFER_MAX_SIZE 8192


#ifdef SAPI_CLIENT
	extern int TpmClientPrintf( UINT8 type, const char *format, ... );
	int (*printfFunction)( UINT8 type, const char *format, ...) = TpmClientPrintf;
#else
	extern int ResMgrPrintf( UINT8 type, const char *format, ... );
	int (*printfFunction)( UINT8 type, const char *format, ...) = ResMgrPrintf;
#endif


static TSS2_TCTI_DRIVER_INFO tbsDriverInfo = { "TPM2 via TBS", "", InitLocalTpmTbs, TeardownLocalTpmTbs };

BYTE resultBuffer[TBS_RESULT_BUFFER_MAX_SIZE];
UINT32 resSize;
void* tbsContext = NULL;

TSS2_RC TbsTpmSendTpmCommand(
	TSS2_TCTI_CONTEXT *tctiContext,       /* in */
	size_t             commandSize,      /* in */
	uint8_t           *commandBuffer     /* in */
	)
{

	TSS2_RC rval = TSS2_RC_SUCCESS;
	resSize = sizeof(resultBuffer);
	
	#ifdef debug_sockets
        (*printffunction)(rmdebugprefix, "localtbs: sending to TPM:\n" );
		debugprintbuffer( (uint8 *)commandBuffer, commandSize);
	#endif    

	TBS_RESULT res = Tbsip_Submit_Command(tbsContext,
		TBS_COMMAND_LOCALITY_ZERO,
		TBS_COMMAND_PRIORITY_NORMAL,
		commandBuffer,
		commandSize,
		resultBuffer,
		&resSize);
	
	if (res != TBS_SUCCESS) {
		(*printfFunction)(NO_PREFIX, "localtbs: Failed to create TBS context\n");
		return 1;
	}
	
	return rval;
}

TSS2_RC TbsTpmReceiveTpmResponse(
	TSS2_TCTI_CONTEXT *tctiContext,     /* in */
	size_t          *response_size,     /* out */
	unsigned char   *response_buffer,    /* in */
	int32_t         timeout
	)
{

	TSS2_RC rval = TSS2_RC_SUCCESS;
	if (resSize == 0 || resSize >= TBS_RESULT_BUFFER_MAX_SIZE) {
		rval = TSS2_TCTI_RC_IO_ERROR;
	}

	#ifdef debug_sockets
        (*printffunction)(rmdebugprefix, "localtbs: received from TPM:\n");
		debugprintbuffer( (uint8 *)resultBuffer, resSize);
	#endif    
	
	for (size_t j = 0; j < resSize; j++) {
		response_buffer[j] = resultBuffer[j];
		(*printfFunction)(NO_PREFIX, "%0");
	}
	response_buffer[resSize] = '\0';
	*response_size = resSize;
	resSize = 0;
	return rval;
}

void TbsTpmFinalize(
    TSS2_TCTI_CONTEXT *tctiContext       /* in */
    )
{
	#ifdef debug_sockets
        (*printffunction)(rmdebugprefix, "localtbs: TbsTpmFinalize called\n");
	#endif    
}

TSS2_RC TbsTpmCancel(
    TSS2_TCTI_CONTEXT *tctiContext
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

	#ifdef debug_sockets
        (*printffunction)(rmdebugprefix, "localtbs: TbsTpmCancel called\n");
	#endif    

    return rval;
}

TSS2_RC TbsTpmSetLocality(
    TSS2_TCTI_CONTEXT *tctiContext,       /* in */
    uint8_t           locality     /* in */
    )
{

	#ifdef debug_sockets
        (*printffunction)(rmdebugprefix, "localtbs: TbsTpmSetLoaclity called\n");
	#endif    

    TSS2_RC rval = TSS2_RC_SUCCESS;
    return rval;
}

TSS2_RC InitLocalTpmTbs (
    TSS2_TCTI_CONTEXT *tctiContext,  // OUT
    size_t *contextSize,             // IN/OUT
    const char *config,              // IN
    const uint64_t magic,
    const uint32_t version,
	const char *interfaceName,
    const uint8_t serverSockets		 // Unused for local TPM.
    )
{
	#ifdef debug_sockets
        (*printffunction)(rmdebugprefix, "localtbs: TbsTpmSetLoaclity called\n");
	#endif    


    TSS2_RC rval = TSS2_RC_SUCCESS;
    char fileName[200];

    if( tctiContext == NULL )
    {
        *contextSize = sizeof( TSS2_TCTI_CONTEXT_INTEL );
        return TSS2_RC_SUCCESS;
    }
	else
	{
		// Init TCTI context.
		((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->magic			 = magic;
		((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->version		 = version;
		((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->transmit		 = TbsTpmSendTpmCommand;
		((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->receive		 = TbsTpmReceiveTpmResponse;
		((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->finalize		 = TbsTpmFinalize;
		((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel		 = TbsTpmCancel;
		((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->getPollHandles = 0;
		((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->setLocality	 = TbsTpmSetLocality;
		((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality	 = 0;
		((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 0;
		((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.rmDebugPrefix = 0;
		((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->currentTctiContext = 0;

		TBS_CONTEXT_PARAMS2 parms;
		parms.includeTpm20 = TRUE;
		parms.version = TBS_CONTEXT_VERSION_TWO;
		TBS_RESULT res = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&parms, &tbsContext);

		if (res != TBS_SUCCESS) {
			(*printfFunction)(NO_PREFIX, "Failed to create TBS context:");
			return 1;
		}

		TPM_DEVICE_INFO info;
		res = Tbsi_GetDeviceInfo(sizeof(info), &info);

		if (res != TBS_SUCCESS) {
			(*printfFunction)(NO_PREFIX, "Failed to get device info from TBS");
			return 1;
		}

		if (info.tpmVersion != TPM_VERSION_20) {
			(*printfFunction)(NO_PREFIX, "Platform does not contain TPM 2.0");
			return 1;
		}
	}

    return rval;
}

TSS2_RC TeardownLocalTpmTbs (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    const char *config,              // IN        
	const char *interfaceName
    )
{
	#ifdef debug_sockets
        (*printffunction)(rmdebugprefix, "localtbs: TeardownLocalTpmTbs called\n");
	#endif    
 
    return TSS2_RC_SUCCESS;
}

TSS2_TCTI_DRIVER_INFO * getTbsDriverInfo()
{
	#ifdef debug_sockets
        (*printffunction)(rmdebugprefix, "localtbs: getTbsDriverInfo called\n");
	#endif    

	return &tbsDriverInfo;
}

#ifdef __cplusplus
}
#endif

#endif
