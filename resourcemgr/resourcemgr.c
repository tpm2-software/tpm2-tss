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

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi

#include <tss2/tpm20.h>
#include <tcti/tcti_device.h>
#include <tcti/tcti_socket.h>
#include "resourcemgr.h"
//#include <sample.h>
#include "sockets.h"
#include "sysapi_util.h"
#include "syscontext.h"
#include "debug.h"

#ifdef  _WIN32
typedef HANDLE THREAD_TYPE; 
#define MAX_COMMAND_LINE_ARGS 6

#elif __linux || __unix

#include <stdarg.h>
#define sprintf_s   snprintf
#define sscanf_s    sscanf
#include <pthread.h>
typedef pthread_t THREAD_TYPE ;
#define ExitThread pthread_exit
#define CloseHandle( handle ) 

#define MAX_COMMAND_LINE_ARGS 7
#else    
#error Unsupported OS--need to add OS-specific support for threading here.        
#endif                

#define DEBUG_RESMGR_INIT        

extern TSS2_RC GetCommands( TSS2_SYS_CONTEXT *resMgrSysContext, TPML_CCA **supportedCommands );
extern UINT8 GetCommandAttributes( TPM_CC commandCode, TPML_CCA *supportedCommands, TPMA_CC *cmdAttributes );

char otherCmdStr[] = "Other CMD";

void *(*rmMalloc)(size_t size) = malloc;
void (*rmFree)(void *entry) = free;

TPML_CCA *supportedCommands;

int GetNumCmdHandles( TPM_CC commandCode, TPML_CCA *supportedCommands )
{
    int rval = -1;
    TPMA_CC cmdAttributes;
    
    if( GetCommandAttributes( commandCode, supportedCommands, &cmdAttributes ) )
    {
        if( commandCode == TPM_CC_FlushContext )
        {
            rval = 1;
        }
        else
        {                
            rval = cmdAttributes.cHandles;
        }
    }

    return rval;
}

int GetNumRspHandles( TPM_CC commandCode, TPML_CCA *supportedCommands )
{
    int rval = 0;
    TPMA_CC cmdAttributes;
    
    if( GetCommandAttributes( commandCode, supportedCommands, &cmdAttributes ) )
    {
		if( cmdAttributes.rHandle == 1 )
	        rval = 1;
    }

    return rval;
}

int ResMgrPrintf( UINT8 type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    if( type == RM_PREFIX )
    {
        PrintRMDebugPrefix();
    }

    va_start( args, format );
    rval = vprintf( format, args );
    va_end (args);

    return rval;
}

int printRMTables = 0;
int rmCommandDebug = 0;
int commandDebug = 0;

#ifdef  _WIN32
UINT8 simulator = 1;
#else
UINT8 simulator = 0;
#endif

enum shutdownStartupSequenceType { TPM_RESET, TPM_RESTART, TPM_RESUME };

TSS2_TCTI_CONTEXT *downstreamTctiContext = 0;
TSS2_SYS_CONTEXT *resMgrSysContext;

TSS2_ABI_VERSION abiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

TSS2_RC ResmgrFixupErrorlevel( TSS2_RC errCode )
{
    if( errCode != TSS2_RC_SUCCESS )
    {
        errCode &= ~TSS2_ERROR_LEVEL_MASK;
        errCode |= TSS2_RESMGR_ERROR_LEVEL;
    }
    return errCode;
}

// Macros for unmarshalling, checking for buffer overruns, and handling errors.
#define RESMGR_UNMARSHAL_UINT8( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_UINT8( buffer, size, currentPtr, value, rval ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
    if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; 

#define RESMGR_UNMARSHAL_UINT16( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_UINT16( buffer, size, currentPtr, value, rval ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
    if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; 

#define RESMGR_UNMARSHAL_UINT32( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_UINT32( buffer, size, currentPtr, value, rval ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
    if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; 

#define RESMGR_UNMARSHAL_UINT64( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_UINT64( buffer, size, currentPtr, value, rval ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
    if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; 

#define RESMGR_UNMARSHAL_SIMPLE_TPM2B( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_Simple_TPM2B( buffer, size, currentPtr, value, rval ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
    if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; 

#define RESMGR_UNMARSHAL_TPMS_CONTEXT( buffer, size, currentPtr, value, rval, exitLoc ) \
    Unmarshal_UINT64( (buffer), (size), (currentPtr), &( (value)->sequence ), (rval) ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
	if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; \
    Unmarshal_UINT32( (buffer), (size), (currentPtr), &( (value)->savedHandle ), (rval) ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
    if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; \
    Unmarshal_UINT32( (buffer), (size), (currentPtr), &( (value)->hierarchy ), (rval) ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
    if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; \
    Unmarshal_Simple_TPM2B_NoSizeCheck( (buffer), (size), (currentPtr), (TPM2B *)&( (value)->contextBlob ), (rval) ); \
    responseRval = ResmgrFixupErrorlevel( *rval ); \
    if( responseRval != TSS2_RC_SUCCESS ) goto exitLoc; 

//
// NOTE: these structures are ONLY used for transient objects, sequences, and
//       sessions.
//

//
// RESOURCE MANAGER OPERATION:
//
// When a transient object or sequence is loaded into TPM memory
// (CreatePrimary, Load, or SequenceStart), the real handle is associated
// with a virtual handle via the virtualHandleMap array, the
// parent virtual handle is saved, and the evicted bit is cleared.
//
// When a command is sent down that has handles in it (virtual or real,
// depending on the type of object), the handle is used to look up the loaded or unloaded
// status.  This is done by searching every element of handleStatuses that
// is used and has the evicted bit set.  If the handle in one of
// these elements matches the handle sent by the command, the
// context will need to be swapped in, and, if it's a transient object,
// the virtual handle replaced with  the real handle.
//
// Eviction of transient objects and sequences is a two step process:
// 1.  Save the context.  The handle is set to the current handle for the
  //     context.  Context saved in the context field.
// 2.  Flush the context.  The handle is set to the virtual handle for the
//     object and the evicted bit is set.
//
// Eviction of sessions is a one step process:
// 1.  Save the context.  Context saved in context field, handle field
//     set to real handle, and evicted bit is set.
//
// Sessions in all commands sent to the TPM are checked for the
// continueSession bit.  If this bit is cleared, then the session's
// corresponding HANDLE_STATUS' used bit is cleared.
//


//
// NOTE:  virtual handle format will be as follows:
// 1.  Upper octet is 0xff
// 2.  When debug is turned on, next nibble, bits 23 - 20 are set to 0xf.
//

typedef struct {
    struct {
        UINT16 loaded : 1;          // Indicates whether this entry's context is loaded
                                    // into the TPM or not.
        UINT16 stClear : 1;         // Only used for objects; indicates whether object
                                    // context is invalidated by TPM Restart.
        UINT16 persistent : 1;      // Only used for objects; indicates whether object
                                    // is persistent or not.
    } status;
    TPM_HANDLE virtualHandle;       // For transient objects and sequences, this is the virtual
                                    //  handle.
                                    // For sessions, this is the real handle at this time.  It
                                    //  could be virtualized in the future if we need it to be.
    TPM_HANDLE realHandle;          // For objects and sequences, this is the real handle if
                                    //  if the object or sequence context is loaded in the TPM.
                                    //  Otherwise, it's 0.
                                    // For sessions, this is the real handle of the session,
                                    //  whether the session is loaded into the TPM or not.
    // NOTE:  parentHandle and hierachy could be coalesced into one field since for a primary
    // object the hierarchy is the parent, and for a non-primary object, the hierarchy is
    // determined by walking up the chain of parents.
    // We chose to add a hierarchy field separate from parentHandle to make the
    // reosurce manager's job easier when change auth commands are done for hiearchies.
    TPM_HANDLE parentHandle;        // For objects, this is the parent handle. 
    TPMI_RH_HIERARCHY hierarchy;    // This is the hierarchy for the object. For sessions and 
                                    //  sequences this is set to TPM_RH_NULL.
    TPMS_CONTEXT context;           // For transient objects, this is saved after the object's
                                    //  context is saved.
                                    // For sessions, this is saved after the session context is
                                    //  flushed.
    UINT64 connectionId;            // Used to identify which connection owns the object,
                                    // sequence, or session.
    void *nextEntry; // Next entry in the list; 0 to terminate list.                                
} RESOURCE_MANAGER_ENTRY;

RESOURCE_MANAGER_ENTRY *entryList = 0;

typedef struct
{
    TPM_HANDLE sessionHandle;
    TPMA_SESSION sessionAttributes;
    UINT8 sessionNum;
    TPM_HANDLE *sessionHandlePtr;
} RM_SESSION_HANDLE_STRUCT;

typedef struct
{
    TPM_HANDLE handle;
    UINT8 handleNum;
} RM_HANDLE_STRUCT;

static RM_HANDLE_STRUCT cmdHandles[3];
static RM_SESSION_HANDLE_STRUCT sessionHandles[3];
static int numHandles;
static int numSessionHandles;
static TPM_HANDLE cmdParentHandle;
static TPM_HANDLE cmdSavedHandle;
static TPM_HANDLE cmdFlushedHandle;
static TPM_HANDLE cmdSequenceUpdateHandle;
static TPM_HANDLE objectHandle;
static TPM_HANDLE persistentHandle;

static UINT8 cmdStClearBit;
static TPM_RH cmdHierarchy;
static TPM_CC currentCommandCode;
static UINT64 cmdConnectionId;
static TPM20_ErrorResponse errorResponse;
static UINT64 lastSessionSequenceNum = 0;
static UINT32 gapMsbBitMask = 0;
static TPMS_CONTEXT cmdObjectContext;

// These are used by logic that handles resource manager structures
// on a Startup command.
// startupType is saved when the startup command response is received and is successful.
// shutdownType is saved when Shutdown command is sent.
// shutdown_state is updated when the Shutdown response is
//   received if the Shutdown was successful.
static TPM_SU startupType = 0;  
static TPM_SU shutdownType = 0;  
static BOOL shutdown_state = 0;

static UINT32 maxCmdSize;
static UINT32 maxRspSize;
static UINT8 *cmdBuffer;
static UINT8 *rspBuffer;

static UINT32 maxActiveSessions;
static UINT32 gapMaxValue;
static UINT32 activeSessionCount = 0;

void  SetDebug( UINT8 debugLevel )
{
    if( debugLevel == DBG_COMMAND )
    {
        commandDebug = 1;
        rmCommandDebug = 0;
        printRMTables = 0;
    }
    else if( debugLevel == DBG_COMMAND_RM )
    {
        commandDebug = 1;
        rmCommandDebug = 1;
        printRMTables = 0;
    }
    else if( debugLevel == DBG_COMMAND_RM_TABLES )
    {
        commandDebug = 1;
        rmCommandDebug = 1;
        printRMTables = 1;
    }
    else
    {
        commandDebug = 0;
        rmCommandDebug = 0;
        printRMTables = 0;
    }
}

//
// Is it a session handle?
//
UINT8 IsSessionHandle( TPM_HANDLE handle )
{
    TPM_HT handleType;

    handleType = handle >> 24;

    if( handleType == TPM_HT_HMAC_SESSION ||
        handleType == TPM_HT_POLICY_SESSION )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

//
// Is it a session handle?
//
UINT8 IsObjectHandle( TPM_HANDLE handle )
{
    TPM_HT handleType;

    handleType = handle >> 24;

    if( handleType == TPM_HT_TRANSIENT ) 
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


#ifdef RM_DEBUG
#define VR_HT_ID    0xf
#define MAX_VIRTUAL_HANDLE 0xfffff
#else
#define VR_HT_ID    0x0
#define MAX_VIRTUAL_HANDLE 0xffffff
#endif

#define VR_HANDLE_ID   ( VR_HT_ID << 20 )

//
// NOTE: FREED_HANDLE_ARRAY_SIZE determines chances of
// leaking track of freed virtual handles.  Larger value
// reduces chances of leaks, but also increases memory usage.
//
#define FREED_HANDLE_ARRAY_SIZE 32

#define UNAVAILABLE_FREED_HANDLE 0xffffffff

TPM_HANDLE freedSessionHandles[FREED_HANDLE_ARRAY_SIZE];
TPM_HANDLE freedObjectHandles[FREED_HANDLE_ARRAY_SIZE];

// This code keeps track of freed virtual handles.
// If no empty slot is available, the virtual handle
// will be lost.
void UpdateFreedVirtualHandleCache( TPM_HANDLE virtualHandle )
{
    TPM_HANDLE *freedHandleArray;
    int i;
    
    if( IsSessionHandle( virtualHandle ) )
    {
        freedHandleArray = freedSessionHandles;
    }
    else if( IsObjectHandle( virtualHandle ) )
    {
        freedHandleArray = freedObjectHandles;
    }
    else
    {
        return;
    }

    for( i = 0; i < FREED_HANDLE_ARRAY_SIZE; i++ )
    {
        if( freedHandleArray[i] == UNAVAILABLE_FREED_HANDLE )
        {
            freedHandleArray[i] = virtualHandle;
            break;
        }
    } 
}

TSS2_RC	GetNewVirtualHandle( TPM_HANDLE realHandle, TPM_HANDLE *newVirtualHandle)
{
    // For now, use this algorithm:  check for freed handles. If any available, use them.
    // if none available, just increment last used virtual handle.
    // This could eventually overrun.  Return an error when that occurs.
    TSS2_RC rval = TSS2_RC_SUCCESS;
    int i;
    
    static UINT32 lastSessionVirtualHandle = 0xffffffff;
    static UINT32 lastObjectVirtualHandle = 0xffffffff;
    UINT8 foundReclaimedHandle = 0;

    UINT32 *lastVirtualHandle;
    TPM_HANDLE *freedHandleArray;
    
    if( IsSessionHandle( realHandle ) )
    {
        lastVirtualHandle = &lastSessionVirtualHandle;
        freedHandleArray = freedSessionHandles;
    }
    else
    {
        lastVirtualHandle = &lastObjectVirtualHandle;
        freedHandleArray = freedObjectHandles;
    }

    for( i = 0; i < FREED_HANDLE_ARRAY_SIZE; i++ )
    {
        if( freedHandleArray[i] != UNAVAILABLE_FREED_HANDLE )
        {
            *newVirtualHandle = ( ( freedHandleArray[i] & HR_HANDLE_MASK ) | ( realHandle & ~HR_HANDLE_MASK ) | VR_HANDLE_ID );
            freedHandleArray[i] = UNAVAILABLE_FREED_HANDLE;
            foundReclaimedHandle = 1;
            break;
        }
    }

    //
    // NOTE: if leaking handles become a problem, could do a search here of an ordered list of currently used handles.
    // Any gaps would be valid candiates for new handles.  The ordering could be done by adding
    // nextSessionVirtHandlePtr and nextObjectVirtHandlePtr elements to the RESOURCE_MANAGER_ENTRY structure
    // and updating these pointers correctly everytime a new element is added.
    //
    // Didn't choose to do this at this time due to possible performance penalty, but keep in mind for future.
    //
    
    if( !foundReclaimedHandle )
    {
        (*lastVirtualHandle)++;

        if( *lastVirtualHandle > MAX_VIRTUAL_HANDLE )
        {
            rval = TSS2_RESMGR_VIRTUAL_HANDLE_OVERFLOW;
        }
        else
        {
            *newVirtualHandle = ( (*lastVirtualHandle & HR_HANDLE_MASK ) | ( realHandle & ~HR_HANDLE_MASK ) | VR_HANDLE_ID );
        }
    }

    return rval;
}

void SetRmErrorLevel( TSS2_RC *rval, TSS2_RC errorLevel )
{
    if( ( ( *rval & TSS2_ERROR_LEVEL_MASK ) == TSS2_SYS_ERROR_LEVEL ) || ( *rval & TSS2_ERROR_LEVEL_MASK ) != 0 )
    {
        // This is a TPM error or a SYSAPI error, so add correct error level.
        *rval |= TSS2_RESMGRTPM_ERROR_LEVEL;
    }
}

// Use tctiContext ptr as connection ID.
// Use tctiContext ptr as connection ID.
// With current implementation this doesn't need to be a function,
// but some OS environments might require a more complex
// implementation.
TSS2_RC GetConnectionId( UINT64 *connectionId, TSS2_TCTI_CONTEXT *tctiContext )
{
    *connectionId = (UINT64)((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->currentConnectSock;

    return TSS2_RC_SUCCESS;
}

void PrintRMTables()
{
    int i;
    RESOURCE_MANAGER_ENTRY *entryPtr;

    if( !printRMTables )
        return;

    ResMgrPrintf( RM_PREFIX, "RM entryList:\n" );
    for( i = 0, entryPtr = entryList; entryPtr != 0; entryPtr = entryPtr->nextEntry, i++ )
    {
        ResMgrPrintf( RM_PREFIX, "Entry: #%d, loaded: %d, virtual/real/parent handle: %8.8x/%8.8x/%8.8x, hierarchy: %8.8x, sequence: %016llX, connectionId: 0x%x\n",
                i, entryPtr->status.loaded, entryPtr->virtualHandle, entryPtr->realHandle, entryPtr->parentHandle,
                entryPtr->hierarchy, entryPtr->context.sequence, entryPtr->connectionId );
    }

    ResMgrPrintf( RM_PREFIX, "lastSessionSequenceNum = %8.8llx\n", lastSessionSequenceNum );
}

TSS2_RC TestForLoadedHandles()
{
    TPMS_CAPABILITY_DATA capabilityData;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPMI_YES_NO moreData;
	UINT32 i;
    
    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_HANDLES, TRANSIENT_FIRST,
            20, &moreData, &capabilityData, 0 );
    if( rval != TSS2_RC_SUCCESS )
        goto endTestForLoadedHandles;
    
    if( capabilityData.data.handles.count != 0 )
    {
        ResMgrPrintf( RM_PREFIX, "Loaded transient object handles: \n" );
        ResMgrPrintf( RM_PREFIX, "" );
        for( i = 0; i < capabilityData.data.handles.count; i++ )
        {
            ResMgrPrintf( NO_PREFIX, "0x%8x, ", capabilityData.data.handles.handle[i] );
        }

        rval = TSS2_RESMGR_UNLOADED_OBJECTS;
    }

    if( rval != TSS2_RC_SUCCESS )
        goto endTestForLoadedHandles;

#if 0    
    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_HANDLES, TPM_HT_LOADED_SESSION,
            20, &moreData, &capabilityData, 0 );
    if( rval != TSS2_RC_SUCCESS )
        goto endTestForLoadedHandles;

    if( capabilityData.data.handles.count != 0 )
    {
        ResMgrPrintf( RM_PREFIX, "Loaded session handles: \n" );
        for( i = 0; i < capabilityData.data.handles.count; i++ )
        {
            ResMgrPrintf( NO_PREFIX, "0x%8x, ", capabilityData.data.handles.handle[i] );
        }
        ResMgrPrintf( NO_PREFIX, "\n" );

        rval = TSS2_RESMGR_UNLOADED_OBJECTS;
    }
#endif
    
endTestForLoadedHandles:
    
    return rval;
}    

TSS2_RC FlushAllLoadedHandles()
{
    TPMS_CAPABILITY_DATA capabilityData;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPMI_YES_NO moreData;
    UINT32 i;

    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_HANDLES, TRANSIENT_FIRST,
            20, &moreData, &capabilityData, 0 );
    if( rval != TSS2_RC_SUCCESS )
        goto endFlushAllLoadedHandles;

    if( capabilityData.data.handles.count != 0 )
    {
        ResMgrPrintf( RM_PREFIX, "Flush loaded transient object handles: \n" );
        ResMgrPrintf( RM_PREFIX, "" );
        for( i = 0; i < capabilityData.data.handles.count; i++ )
        {
            ResMgrPrintf( NO_PREFIX, "0x%8x, ", capabilityData.data.handles.handle[i] );
            rval = Tss2_Sys_FlushContext( resMgrSysContext, capabilityData.data.handles.handle[i] );
            if( rval != TSS2_RC_SUCCESS )
            {
                SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
                goto endFlushAllLoadedHandles;
            }
        }
        ResMgrPrintf( NO_PREFIX, "\n" );
    }

    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_HANDLES, LOADED_SESSION_FIRST,
            20, &moreData, &capabilityData, 0 );
    if( rval != TSS2_RC_SUCCESS )
        goto endFlushAllLoadedHandles;

    if( capabilityData.data.handles.count != 0 )
    {
        ResMgrPrintf( RM_PREFIX, "Flush loaded session handles: \n" );
        for( i = 0; i < capabilityData.data.handles.count; i++ )
        {
            ResMgrPrintf( NO_PREFIX, "0x%8x, ", capabilityData.data.handles.handle[i] );
            rval = Tss2_Sys_FlushContext( resMgrSysContext, capabilityData.data.handles.handle[i] );
            if( rval != TSS2_RC_SUCCESS )
            {
                SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
                goto endFlushAllLoadedHandles;
            }
        }
        ResMgrPrintf( NO_PREFIX, "\n" );
    }

endFlushAllLoadedHandles:

    return rval;
}



TSS2_RC AddEntry( TPM_HANDLE virtualHandle, TPM_HANDLE realHandle, TPM_HANDLE parentHandle,
    TPMI_RH_HIERARCHY hierarchy, UINT64 connectionId )
{
    RESOURCE_MANAGER_ENTRY **entryPtr, *newEntry;
            
    // Find end of list
    for( entryPtr = &entryList; *entryPtr != 0; entryPtr = (RESOURCE_MANAGER_ENTRY **)&( (*entryPtr)->nextEntry ) )
        ;

    // Allocate space for new record
    newEntry = (*rmMalloc)( sizeof( RESOURCE_MANAGER_ENTRY ) );
    if( newEntry == 0 )
        return TSS2_RESMGR_MEMALLOC_FAILED;

    // Populate it.
    *entryPtr = newEntry;
    newEntry->virtualHandle = virtualHandle;
    newEntry->realHandle = realHandle;
    newEntry->parentHandle = parentHandle;
    newEntry->hierarchy = hierarchy;
    newEntry->connectionId = connectionId;
    newEntry->status.loaded = 1;
    newEntry->status.stClear = 0;
    newEntry->status.persistent = 0;
    newEntry->nextEntry = 0;
    
    return TSS2_RC_SUCCESS;
}

TSS2_RC RemoveEntry(RESOURCE_MANAGER_ENTRY *entry)
{
    RESOURCE_MANAGER_ENTRY **predEntryPtr;

    if( IsSessionHandle( entry->virtualHandle ) || IsObjectHandle( entry->virtualHandle ) )
	{
	    UpdateFreedVirtualHandleCache( entry->virtualHandle );
	}
    
    if( entry == entryList )
        entryList = (RESOURCE_MANAGER_ENTRY *)entryList->nextEntry;
    else
    {
        // Find predecessor.
        for( predEntryPtr = &entryList; (*predEntryPtr)->nextEntry != entry;
                predEntryPtr = (RESOURCE_MANAGER_ENTRY **)&( (*predEntryPtr)->nextEntry ) )
            ;

        (*predEntryPtr)->nextEntry = entry->nextEntry;
    }
    
    (*rmFree)(entry);

    return TSS2_RC_SUCCESS;
}

enum findType{ RMFIND_VIRTUAL_HANDLE, RMFIND_REAL_HANDLE, RMFIND_PARENT_HANDLE, RMFIND_HIERARCHY, RMFIND_SESSION_SEQUENCE_NUMBER };

//
//  firstEntry is the starting point of the search
//	field is the field in the entry that has to match and
//    is one of:  RMFIND_VIRTUAL_HANDLE, RMFIND_REAL_HANDLE,
//    RMFIND_PARENT_HANDLE, RMFIND_HIERARCHY
// 	matchSpec is the value that has to match the field.
//    foundEntry is pointer to first found matching entry
//
TSS2_RC FindEntry(RESOURCE_MANAGER_ENTRY *firstEntry,
    enum findType type, UINT64 matchSpec, RESOURCE_MANAGER_ENTRY **foundEntryPtr)
{
    UINT8 foundEntry = 0;
    
    for( *foundEntryPtr = entryList; *foundEntryPtr != 0; *foundEntryPtr = (*foundEntryPtr)->nextEntry )
    {
        if( type == RMFIND_VIRTUAL_HANDLE )
        {
            if( ( TPM_HANDLE)matchSpec == (*foundEntryPtr)->virtualHandle )
            {
                foundEntry = 1;
                break;
            }
        }
        else if( type == RMFIND_REAL_HANDLE )
        {
            if( ( TPM_HANDLE)matchSpec == (*foundEntryPtr)->realHandle )
            {
                foundEntry = 1;
                break;
            }
        }
        else if( type == RMFIND_PARENT_HANDLE )
        {
            if( ( TPM_HANDLE)matchSpec == (*foundEntryPtr)->parentHandle )
            {
                foundEntry = 1;
                break;
            }
        }
        else if( type == RMFIND_HIERARCHY )
        {
            if( ( TPM_HANDLE)matchSpec == (*foundEntryPtr)->hierarchy )
            {
                foundEntry = 1;
                break;
            }
        }
        else if( type == RMFIND_SESSION_SEQUENCE_NUMBER )
        {
            if( IsSessionHandle( (*foundEntryPtr)->virtualHandle ) && ( matchSpec == (*foundEntryPtr)->context.sequence ) )
            {
                foundEntry = 1;
                break;
            }
        }
        else
            return TSS2_RESMGR_BAD_FINDFIELD;
    }

    if( foundEntry == 0 )
        return TSS2_RESMGR_FIND_FAILED;
    else
        return TSS2_RC_SUCCESS;
}

TSS2_RC EvictContext(TPM_HANDLE virtualHandle)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    RESOURCE_MANAGER_ENTRY *foundEntryPtr;

    // Find entry corresponding to this virtual handle.
    rval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, virtualHandle, &foundEntryPtr);
    if( rval != TSS2_RC_SUCCESS )
        return rval;

    if( foundEntryPtr->status.loaded )
    {
        // Now save the context of the object, sequence, or session.  In the case of sessions, this
        // also removes the context from the TPM.  For the others, a FlushContext command is required
        // to remove the context.
        rval = Tss2_Sys_ContextSave( resMgrSysContext, foundEntryPtr->realHandle, &(foundEntryPtr->context) );
        if( rval == TSS2_RC_SUCCESS )
        {
            lastSessionSequenceNum = foundEntryPtr->context.sequence;
        
            if( !IsSessionHandle( virtualHandle ) )
            {
                rval = Tss2_Sys_FlushContext( resMgrSysContext, foundEntryPtr->realHandle );
                if( rval != TSS2_RC_SUCCESS )
                {
                    SetRmErrorLevel( &rval, TSS2_RESMGRTPM_ERROR_LEVEL );
                }
            }
        }
        else
        {
            SetRmErrorLevel( &rval, TSS2_RESMGRTPM_ERROR_LEVEL );
        }
    }
    else
    {
        rval = TSS2_RESMGR_FIND_FAILED;
    }

    if( rval == TSS2_RC_SUCCESS )
    {
        foundEntryPtr->status.loaded = 0;
        if( !IsSessionHandle( virtualHandle ) )
        {
            foundEntryPtr->realHandle = 0;
        }
    }

    return rval;
}

TSS2_RC FindOldestSession(RESOURCE_MANAGER_ENTRY **oldestSessionEntry)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    
    RESOURCE_MANAGER_ENTRY *currEntry;

    *oldestSessionEntry = 0;

    // Find oldest session.

    // First search for oldest session entry with same MSB as lastSessionSequenceNum
    // and that is greater than lastSessionSequenceNum.
    for( currEntry = entryList; currEntry != 0; currEntry = currEntry->nextEntry )
    {
        if( IsSessionHandle( currEntry->virtualHandle ) )
        {
            if( ( currEntry->context.sequence & gapMsbBitMask ) == ( lastSessionSequenceNum & gapMsbBitMask ) ) 
            {
                if( currEntry->context.sequence > lastSessionSequenceNum )
                {
                    if( (*oldestSessionEntry) == 0 || ( currEntry->context.sequence < (*oldestSessionEntry)->context.sequence ) )
                    {
                        (*oldestSessionEntry) = currEntry;
                    }
                }
            }
        }
    }

    // If not successful, search other interval for oldest session entry.
    if( *oldestSessionEntry == 0 )
    {
        for( currEntry = entryList; currEntry != 0; currEntry = currEntry->nextEntry )
        {
            if( IsSessionHandle( currEntry->virtualHandle ) )
            {
                if( ( currEntry->context.sequence & gapMsbBitMask ) != ( lastSessionSequenceNum & gapMsbBitMask ) ) 
                {
                    if( (*oldestSessionEntry) == 0 || ( currEntry->context.sequence < (*oldestSessionEntry)->context.sequence ) )
                    {
                        (*oldestSessionEntry) = currEntry;
                    }
                }
            }
        }
    }

    // If not successful, search current interval sessions for oldest session entry with sequence # less than last session.
    if( (*oldestSessionEntry) == 0 )
    {
        for( currEntry = entryList; currEntry != 0; currEntry = currEntry->nextEntry )
        {
            if( IsSessionHandle( currEntry->virtualHandle ) )
            {
                if( ( currEntry->context.sequence & gapMsbBitMask ) == ( lastSessionSequenceNum & gapMsbBitMask ) ) 
                {
                    if( currEntry->context.sequence < lastSessionSequenceNum )
                    {
                        if( (*oldestSessionEntry) == 0 || ( currEntry->context.sequence < (*oldestSessionEntry)->context.sequence ) )
                        {
                            (*oldestSessionEntry) = currEntry;
                        }
                    }
                }
            }
        }
    }
    return rval;
}

TSS2_RC HandleGap()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT32 otherIntervalSessionsCount = 0;
    UINT32 currIntervalSequenceNumsLeft = 0;
    RESOURCE_MANAGER_ENTRY *entryPtr, *oldestSessionEntryPtr;

    // Find the number of sessions in the interval other than the current one.
    for( entryPtr = entryList; entryPtr != 0; entryPtr = entryPtr->nextEntry )
    {
        if( IsSessionHandle( entryList->virtualHandle ) )
        {
            if( lastSessionSequenceNum & gapMsbBitMask )
            {
                // lastSessionSequenceNum is odd.
                if( ( entryPtr->context.sequence & gapMsbBitMask ) == 0 )
                {
                    otherIntervalSessionsCount++;
                }
            }
            else
            {
                // lastSessionSequenceNum is even.
                if( ( entryPtr->context.sequence & gapMsbBitMask ) == gapMsbBitMask )
                {
                    otherIntervalSessionsCount++;
                }
            }
        }
    }

    // Find the number of sequence numbers left in current interval.
    if( lastSessionSequenceNum & gapMsbBitMask )
    {
        // lastSessionSequenceNum is odd.
        currIntervalSequenceNumsLeft = gapMaxValue - ((UINT32)lastSessionSequenceNum & gapMaxValue );
    }
    else
    {
        // lastSessionSequenceNum is even.
        currIntervalSequenceNumsLeft = (gapMsbBitMask - 1) - ((UINT32)lastSessionSequenceNum & ( gapMsbBitMask - 1 ) );
    }

    // Sanity check to make sure that we didn't have some kind of math
    // or other logic error.
    if( otherIntervalSessionsCount > gapMaxValue / 2 )
        return TSS2_RESMGR_GAP_HANDLING_FAILED;
   
    // Test to see if gapping actions are needed.
    if( ( otherIntervalSessionsCount != 0 ) &&
            otherIntervalSessionsCount >= currIntervalSequenceNumsLeft )
    {
        UINT32 i;

        for( i = 0; i < otherIntervalSessionsCount; i++ )
        {
            // Find oldest session.

            rval = FindOldestSession( &oldestSessionEntryPtr );
            if( rval == TSS2_RC_SUCCESS )
            {

                if( oldestSessionEntryPtr )
                {
#ifdef DEBUG_GAP_HANDLING
                    ResMgrPrintf( RM_PREFIX, "gap event occurred\n" );
#endif                
                    // Perform gapping actions 
                    rval = Tss2_Sys_ContextLoad( resMgrSysContext, &( oldestSessionEntryPtr->context ), &( oldestSessionEntryPtr->realHandle ) );
                    if( rval == TSS2_RC_SUCCESS )
                    {
                        lastSessionSequenceNum++;
                        rval = Tss2_Sys_ContextSave( resMgrSysContext, oldestSessionEntryPtr->realHandle, &(oldestSessionEntryPtr->context) );
                        if( rval != TSS2_RC_SUCCESS )
                        {
                            SetRmErrorLevel( &rval, TSS2_RESMGRTPM_ERROR_LEVEL );
                        }
                    }
                    else
                    {
                        SetRmErrorLevel( &rval, TSS2_RESMGRTPM_ERROR_LEVEL );
                    }
                }
            }
        }
    }
    return rval;
}

//
//  if ( connectionId matches that of rmElement) && virtualHandle matches element in list
//    load context into TPM
//    updated loaded bit
//    for objects and sequences: update real handle
//
TSS2_RC LoadContext( TPM_HANDLE virtualHandle, UINT64 connectionId, TPM_HANDLE *handlePtr, UINT8 authArea, UINT8 sessionNum )
{
    TSS2_RC rval = 0;
    RESOURCE_MANAGER_ENTRY *foundEntryPtr;
    
    // Find entry corresponding to this virtual handle.
    rval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, virtualHandle, &foundEntryPtr );
    if( rval != TSS2_RC_SUCCESS )
    {
        // If it's a session handle,
        if( IsSessionHandle( virtualHandle ) )
        {
            if( authArea )
            {
                // ...and it's in the auth area.
                // Return TPM_RC_S + TPM_RC_VALUE + session # shifted left 8 bits
                rval = TSS2_RESMGRTPM_ERROR_LEVEL + TPM_RC_S + TPM_RC_VALUE + ( sessionNum << 8 );
            }
            else
            {
                // ...and it's in the handle area.
                // Return TPM_RC_S + TPM_RC_HANDLE + handle # shifted left 8 bits
                rval = TSS2_RESMGRTPM_ERROR_LEVEL + TPM_RC_HANDLE + ( sessionNum << 8 );
            }
        }
        goto exitLoadContext;
    }

    if( connectionId != foundEntryPtr->connectionId )
    {
        rval = TSS2_RESMGR_UNOWNED_HANDLE;
        goto exitLoadContext;
    }

    if( IsSessionHandle( virtualHandle ) )
    {
        rval = HandleGap();
        if( rval != TSS2_RC_SUCCESS )
            goto exitLoadContext;
    }

    if( foundEntryPtr->status.persistent == 0 )
    {
        rval = Tss2_Sys_ContextLoad( resMgrSysContext, &( foundEntryPtr->context ), &( foundEntryPtr->realHandle ) );
        if( rval != TSS2_RC_SUCCESS )
        {
            SetRmErrorLevel( &rval, TSS2_RESMGRTPM_ERROR_LEVEL );
            goto exitLoadContext;
        }
    }

    if( IsSessionHandle( virtualHandle ) )
    {
        lastSessionSequenceNum++;
    }

    foundEntryPtr->status.loaded = 1;
    if( handlePtr != 0 )
    {
        *handlePtr = CHANGE_ENDIAN_DWORD( foundEntryPtr->realHandle );
    }

exitLoadContext:
    
    return rval;
}

//
// Used to weed out handles that aren't resource managed.
//
UINT8 HandleWeCareAbout( TPM_HANDLE handle )
{
    TPM_HT handleType;

    handleType = handle >> 24;

    if( handleType == TPM_HT_HMAC_SESSION ||
        handleType == TPM_HT_POLICY_SESSION ||
        handleType == TPM_HT_TRANSIENT )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void ClearHierarchy( TPMI_RH_HIERARCHY hierarchy )
{
    RESOURCE_MANAGER_ENTRY *foundEntryPtr, *nextEntry;
    TSS2_RC rval;
    
    nextEntry = entryList;

    while( nextEntry )
    {
        rval = FindEntry( nextEntry, RMFIND_HIERARCHY, hierarchy, &foundEntryPtr);
        if( rval == TSS2_RC_SUCCESS )
        {
            nextEntry = foundEntryPtr->nextEntry;
            (void) RemoveEntry( foundEntryPtr );
        }
        else
            break;
    }
}

UINT8 GetStClear( TPM2B_PUBLIC *inPublic )
{
    return( inPublic->t.publicArea.objectAttributes.stClear );
}

void CreateErrorResponse( TSS2_RC responseCode )
{
    errorResponse.tag = CHANGE_ENDIAN_WORD( TPM_ST_NO_SESSIONS );
    errorResponse.responseSize = CHANGE_ENDIAN_DWORD( sizeof( TPM20_ErrorResponse ) );
    errorResponse.responseCode = CHANGE_ENDIAN_DWORD( responseCode );
}

void SendErrorResponse( SOCKET sock )
{
    UINT32 numBytes = CHANGE_ENDIAN_DWORD( sizeof( TPM20_ErrorResponse ) );
    UINT32 trash = 0;

    sendBytes( sock, (char *)&numBytes, 4 );
    sendBytes( sock, (char *)&errorResponse, sizeof( TPM20_ErrorResponse ) );
    sendBytes( sock, (char *)&trash, 4 );        
}

void CopyErrorResponse( UINT32 *response_size, uint8_t *response_buffer )
{
    int i;
    
    for( i = 0; i < sizeof(TPM20_ErrorResponse); i++ )
    {
        response_buffer[i] = ( (UINT8 *)&errorResponse )[i];
    }
    *response_size = sizeof(TPM20_ErrorResponse);
}

static int numSessionHandles;
static UINT8 rmErrorDuringSend = 0;

TSS2_RC EvictOldestSession()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    RESOURCE_MANAGER_ENTRY *oldestSessionEntry;

    // Find oldest session.
    rval = FindOldestSession( &oldestSessionEntry );
    if( rval == TPM_RC_SUCCESS )
    {
        if( oldestSessionEntry )
        {
            // Kick it out--flush it.
            rval = Tss2_Sys_FlushContext( resMgrSysContext, oldestSessionEntry->realHandle );
            if( rval == TPM_RC_SUCCESS )
            {
                activeSessionCount--;

                // Delete its entry in table.
                rval = RemoveEntry(oldestSessionEntry);
            }
            else
            {
                SetRmErrorLevel( &rval, TSS2_RESMGRTPM_ERROR_LEVEL );
            }
        }
    }
    
    return rval;
}

// Update the context of the oldest session
TSS2_RC ContextGapUpdateOldestSession()
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    RESOURCE_MANAGER_ENTRY *oldestSessionEntry;

    // Find oldest session.
    rval = FindOldestSession( &oldestSessionEntry );

    if( oldestSessionEntry )
    {
        if( rval == TPM_RC_SUCCESS )
        {

            // Load it.
            rval = Tss2_Sys_ContextLoad( resMgrSysContext, &(oldestSessionEntry->context), &(oldestSessionEntry->realHandle) );
            if( rval == TPM_RC_SUCCESS )
            {
                lastSessionSequenceNum++;

                // Save it.
                rval = Tss2_Sys_ContextSave( resMgrSysContext, oldestSessionEntry->realHandle, &(oldestSessionEntry->context) );
                if( rval != TSS2_RC_SUCCESS )
                {
                    SetRmErrorLevel( &rval, TSS2_RESMGRTPM_ERROR_LEVEL );
                }
            }
            else
            {
                SetRmErrorLevel( &rval, TSS2_RESMGRTPM_ERROR_LEVEL );
            }
        }
    }
    return rval;
}

TSS2_RC ResourceMgrSendTpmCommand(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t          command_size,       /* in */
    uint8_t         *command_buffer     /* in */
    )
{
    TPM_HANDLE *handlePtr;
    int i = 0;
    TPM_RC rval = TSS2_RC_SUCCESS;
    TPM_RC responseRval = TSS2_RC_SUCCESS;
    UINT8 *endAuth;
    RESOURCE_MANAGER_ENTRY *foundEntryPtr;
    UINT8 *currentPtr = command_buffer;
    TPM_ST tag;
	UINT32 authAreaSize;
	TPM2B_PUBLIC inPublic = { { CHANGE_ENDIAN_DWORD( sizeof( TPM2B_PUBLIC ) - 2), } };
            
    RESMGR_UNMARSHAL_UINT16( command_buffer, command_size, &currentPtr, &tag, &responseRval, SendCommand );
    RESMGR_UNMARSHAL_UINT32( command_buffer, command_size, &currentPtr, 0, &responseRval, SendCommand );
    RESMGR_UNMARSHAL_UINT32( command_buffer, command_size, &currentPtr, &currentCommandCode, &responseRval, SendCommand );

    rmErrorDuringSend = 0;

    rmDebugPrefix = 1;
    //
    // DO RESOURCE MGR THINGS.
    //
    
    if( rmCommandDebug == 1 )
    {
        ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;
    }
    else
    {
        ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_DISABLED;
    }

    numHandles = GetNumCmdHandles( currentCommandCode, supportedCommands );
    if( numHandles == -1 )
    {
        // Since we can't get any info about the command, just send it to TPM and
        // let TPM deal with it.
        goto SendCommand;
    }
    
    for( i = 0; i < numHandles; i++ )
    {
        RESMGR_UNMARSHAL_UINT32( command_buffer, command_size, &currentPtr, &( cmdHandles[i].handle), &responseRval, SendCommand );
        cmdHandles[i].handleNum = i + 1;
    }
    
    // Get list of session handles
    // If sessions are present, record the session handles.
	i = 0;
    if( tag == TPM_ST_SESSIONS )
    {
        RESMGR_UNMARSHAL_UINT32( command_buffer, command_size, &currentPtr, &authAreaSize, &responseRval, SendCommand );
        
        // Get end of auth area.
        endAuth = (UINT8 *)currentPtr + authAreaSize;

        // Now walk through sessions and check for session being ended.
        for( i = 0; (UINT8 *)currentPtr < endAuth; i++ )
        {
            // Save session handle
            sessionHandles[i].sessionHandlePtr = (TPM_HANDLE *)currentPtr;
            RESMGR_UNMARSHAL_UINT32( command_buffer, command_size, &currentPtr, &( sessionHandles[i].sessionHandle ), &responseRval, SendCommand );

            // Skip past nonce
            RESMGR_UNMARSHAL_SIMPLE_TPM2B( command_buffer, command_size, &currentPtr, 0, &responseRval, SendCommand );

            RESMGR_UNMARSHAL_UINT8( command_buffer, command_size, &currentPtr, (UINT8 *)&( sessionHandles[i].sessionAttributes ), &responseRval, SendCommand );
            sessionHandles[i].sessionNum = i + 1;
            
            // Skip past auth.
            inPublic.b.size = CHANGE_ENDIAN_WORD( *(UINT16 *)currentPtr );
            RESMGR_UNMARSHAL_SIMPLE_TPM2B( command_buffer, command_size, &currentPtr, 0, &responseRval, SendCommand );
        }
    }
    
    numSessionHandles = i;
        
    switch( currentCommandCode )
    {
        case TPM_CC_StartAuthSession:
            // This command must always pass, so if we already have
            // maxActiveSessions, oldest one will need to be evicted.
            if( activeSessionCount >= maxActiveSessions )
            {
                responseRval = EvictOldestSession();
                if( responseRval != TSS2_RC_SUCCESS )
                    goto SendCommand;
            }

            responseRval = HandleGap();
            if( responseRval != TSS2_RC_SUCCESS )
                goto SendCommand;
            
            break;
        case TPM_CC_Create:
            cmdParentHandle = cmdHandles[0].handle;
            responseRval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, cmdParentHandle, &foundEntryPtr );
            if( responseRval != TSS2_RC_SUCCESS )
            {
                goto SendCommand;
            }
            cmdHierarchy = foundEntryPtr->hierarchy;

            break;
        case TPM_CC_Load:
            cmdParentHandle = cmdHandles[0].handle;
            responseRval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, cmdParentHandle, &foundEntryPtr );
            if( responseRval != TSS2_RC_SUCCESS )
            {
                goto SendCommand;
            }
            cmdHierarchy = foundEntryPtr->hierarchy;

            // Skip past inPrivate param.
            RESMGR_UNMARSHAL_SIMPLE_TPM2B( command_buffer, command_size, &currentPtr, 0, &responseRval, SendCommand );

            // Get stClear bit.
            inPublic.b.size = CHANGE_ENDIAN_WORD( *(UINT16 *)currentPtr );
            RESMGR_UNMARSHAL_SIMPLE_TPM2B( command_buffer, command_size, &currentPtr, &( inPublic.b ), &responseRval, SendCommand );
            cmdStClearBit = inPublic.t.publicArea.objectAttributes.stClear;

            break;
        case TPM_CC_LoadExternal:
            cmdParentHandle = TPM_RH_NULL;

            // Skip past inPrivate.
            RESMGR_UNMARSHAL_SIMPLE_TPM2B( command_buffer, command_size, &currentPtr, 0, &responseRval, SendCommand );

            // Unmarshal inPublic and get stClear bit.
            inPublic.b.size = CHANGE_ENDIAN_WORD( *(UINT16 *)currentPtr );
            RESMGR_UNMARSHAL_SIMPLE_TPM2B( command_buffer, command_size, &currentPtr, &( inPublic.b ), &responseRval, SendCommand );
            cmdStClearBit = inPublic.t.publicArea.objectAttributes.stClear;

            RESMGR_UNMARSHAL_UINT32( command_buffer, command_size, &currentPtr, &cmdHierarchy, &responseRval, SendCommand );
            break;
        case TPM_CC_CreatePrimary:
            // save dummy handle as parent
            cmdParentHandle = 0;
            cmdHierarchy = cmdHandles[0].handle;

            // Get pointer to inPublic parameter.  We will use this
            // to get the stClear bit for the created object.

            // Skip past inSensitive param.
            RESMGR_UNMARSHAL_SIMPLE_TPM2B( command_buffer, command_size, &currentPtr, 0, &responseRval, SendCommand );
            
            // Unmarshal inPublic and get stClear bit.
            inPublic.b.size = CHANGE_ENDIAN_WORD( *(UINT16 *)currentPtr );
            RESMGR_UNMARSHAL_SIMPLE_TPM2B( command_buffer, command_size, &currentPtr, &( inPublic.b ), &responseRval, SendCommand );
            cmdStClearBit = inPublic.t.publicArea.objectAttributes.stClear;

            break;
        case TPM_CC_HMAC_Start:
        case TPM_CC_HashSequenceStart:
            // save dummy handle as parent
            cmdParentHandle = 0;
            cmdHierarchy = TPM_RH_NULL;
            break;
        case TPM_CC_ContextSave:
            cmdSavedHandle = cmdHandles[0].handle;
            break;
        case TPM_CC_ContextLoad:
            RESMGR_UNMARSHAL_TPMS_CONTEXT( command_buffer, command_size, &currentPtr, &cmdObjectContext, &responseRval, SendCommand );
            cmdHierarchy = cmdObjectContext.hierarchy;
            break;
        case TPM_CC_FlushContext:
            cmdFlushedHandle = cmdHandles[0].handle;
            break;
        case TPM_CC_Startup:
            RESMGR_UNMARSHAL_UINT16( command_buffer, command_size, &currentPtr, &startupType, &responseRval, SendCommand );
            break;
        case TPM_CC_Shutdown:
            RESMGR_UNMARSHAL_UINT16( command_buffer, command_size, &currentPtr, &shutdownType, &responseRval, SendCommand );
            break;
        case TPM_CC_SequenceUpdate:
            cmdSequenceUpdateHandle = cmdHandles[0].handle;
            break;
        case TPM_CC_EvictControl:
            objectHandle = cmdHandles[1].handle;
            RESMGR_UNMARSHAL_UINT32( command_buffer, command_size, &currentPtr, &persistentHandle, &responseRval, SendCommand );
            break;
    }

    if( responseRval != TSS2_RC_SUCCESS )
        goto SendCommand;
    
    responseRval = GetConnectionId( &cmdConnectionId, tctiContext );
    if( responseRval != TSS2_RC_SUCCESS )
        goto SendCommand;

    // Load context for any sessions specified in the authorizations area.
    if( numSessionHandles )
    {
        for( i = 0; i < numSessionHandles; i ++ )
        {
            if( HandleWeCareAbout( sessionHandles[i].sessionHandle ) )
            {
                responseRval = LoadContext( sessionHandles[i].sessionHandle, cmdConnectionId, sessionHandles[i].sessionHandlePtr, 1, sessionHandles[i].sessionNum );
                if( responseRval != TSS2_RC_SUCCESS )
                    goto SendCommand;
            }
        }
    }

    // Load context for any objects or sequences needed and insert
    // real handle into byte stream.
    if( numHandles )
    {
        handlePtr = &( ( (TPM20_Header_In *)command_buffer )->commandCode ) + 1;
        
        for( i = 0; i < numHandles; i ++ )
        {
            if( HandleWeCareAbout( cmdHandles[i].handle ) )
            {
                // Don't need to load context, if we're just flushing a session.
                // Otherwise, we do.
                if( !( currentCommandCode == TPM_CC_FlushContext &&
                        IsSessionHandle( cmdHandles[i].handle ) ) )
                {
                    responseRval = LoadContext( cmdHandles[i].handle, cmdConnectionId, &handlePtr[i], 0, cmdHandles[i].handleNum );
                    if( responseRval != TSS2_RC_SUCCESS )
                        goto SendCommand;
                }
                else
                {
                    // Need to virtualize the session handle, but don't need to load the session context.

                    // Find entry corresponding to the session's virtual handle.
                    rval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, cmdHandles[i].handle, &foundEntryPtr );
                    if( rval != TSS2_RC_SUCCESS )
                    {
                        // Return TPM_RC_S + TPM_RC_HANDLE + handle # shifted left 8 bits
                        rval = TSS2_RESMGRTPM_ERROR_LEVEL + TPM_RC_P + TPM_RC_1 + TPM_RC_HANDLE;

                        goto SendCommand;
                    }

                    handlePtr[i] = CHANGE_ENDIAN_DWORD( foundEntryPtr->realHandle );
                }
            }
        }
    }
    
SendCommand:
  
    rmDebugPrefix = 0;

    ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;

    if( responseRval == TSS2_RC_SUCCESS )
    {
        if( commandDebug == 1 )
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;
        }
        else
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_DISABLED;
        }

        //
        // Set locality for command
        //
        rval = (((TSS2_TCTI_CONTEXT_COMMON_CURRENT *)tctiContext)->setLocality)(
                (TSS2_TCTI_CONTEXT *)downstreamTctiContext, ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality );

        if( rval == TSS2_RC_SUCCESS )
        {
            //
            // SEND COMMAND TO TPM.
            //
            rval = (((TSS2_TCTI_CONTEXT_COMMON_CURRENT *)downstreamTctiContext)->transmit)(
                    (TSS2_TCTI_CONTEXT *)downstreamTctiContext,
                    command_size, command_buffer );

            if( rval == TSS2_RC_SUCCESS )
            {
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 1;
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->currentTctiContext = tctiContext;
            }
        }
    }
    else
    {
        // Create response packet and set flag to indicate that it should be
        // returned when response is requested.
        CreateErrorResponse( responseRval );
        rmErrorDuringSend = 1;
    }

    PrintRMTables();

    return rval;
}

// NOTE:  the handles array should be virtualized handles.
TSS2_RC EvictEntities( int numHandles, TPM_HANDLE *handles )
{
    int i;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    
    for( i = 0; i < numHandles; i++ )
    {
        RESOURCE_MANAGER_ENTRY *foundEntryPtr;

        if( HandleWeCareAbout( handles[i] ) )
        {
            rval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, handles[i], &foundEntryPtr);
            if( rval != TSS2_RC_SUCCESS )
            {
                goto returnFromEvictEntities;
            }

            // If sequence is being ended, and we're looking at the
            // sequence handle, remove the sequence from the list of
            // entries.
            if( ( currentCommandCode == TPM_CC_SequenceComplete && i == 0 ) ||
                    ( currentCommandCode == TPM_CC_EventSequenceComplete && i == 1 ) )
            {
                (void) RemoveEntry( foundEntryPtr );
            }
            // Otherwise, just evict the object or sequence.
            else
            {
                rval = EvictContext( foundEntryPtr->virtualHandle );
                if( rval != TSS2_RC_SUCCESS )
                {
                    goto returnFromEvictEntities;
                }
            }
        }
    }

returnFromEvictEntities:
    
    return rval;
}

UINT8 PersistentHandle( TPM_HANDLE handle )
{
    TPM_HT handleType;

    handleType = handle >> 24;

    if( handleType == TPM_HT_PERSISTENT )
        return 1;
    else
        return 0;
}

TSS2_RC ResourceMgrReceiveTpmResponse(
    TSS2_TCTI_CONTEXT   *tctiContext,
    UINT32              *response_size,     /* out */
    uint8_t             *response_buffer,   /* in */
    int32_t             timeout
    )
{
    TPM_RC responseCode = TSS2_RC_SUCCESS, responseRval = TSS2_RC_SUCCESS;

    // This one is used for capturing errors that occur during exit process.
    // Used to preserve previous errors. Only return error that occurred during
    // exiting if no previous error.
    TPM_RC returnResponseRval = TSS2_RC_SUCCESS;

    TPM_RC testForLoadedSessionsOrObjectsRval = TSS2_RC_SUCCESS; 
    
    int i;
    TPM_ST tag;
    int numResponseHandles = 0;
    UINT8 *endAuth;
    int rval = TSS2_RC_SUCCESS;
    RESOURCE_MANAGER_ENTRY *foundEntryPtr;
    UINT8 commandPassed = 0;
    UINT8 *currentPtr, *savedCurrentPtr;
    UINT32 responseHandles[3] = { 0, 0, 0 };
    TPMA_SESSION sessionAttributes;

    currentPtr = response_buffer;
    
    // Evict all objects, sessions, and sequences.  This leaves the TPM
    // in a fresh state, e.g. with none of these things taking up
    // internal RAM.  This means that we never have to react to
    // out of memory errors which makes the resource manager much
    // simpler.
    
    if( *response_size < ( sizeof( TPM20_Header_Out ) - 1 ) )
    {
        responseRval = TSS2_RESMGR_INSUFFICIENT_RESPONSE;
    }
    else if( rmErrorDuringSend )
    {
        // If an RM error occurred during the send, just return
        // the error response byte stream here.
        CopyErrorResponse( response_size, response_buffer );
        rmDebugPrefix = 1;
        responseRval = CHANGE_ENDIAN_DWORD( ( (TPM20_ErrorResponse *)response_buffer )->responseCode );
        goto returnFromResourceMgrReceiveTpmResponse;
    }
    else
    {
        if( commandDebug == 1 )
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;
        }
        else
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_DISABLED;
        }

        //
        // Set locality for response
        //
        rval = (((TSS2_TCTI_CONTEXT_COMMON_CURRENT *)downstreamTctiContext)->setLocality)(
                (TSS2_TCTI_CONTEXT *)downstreamTctiContext, ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality );
        if( rval != TSS2_RC_SUCCESS )
        {
            goto returnFromResourceMgrReceiveTpmResponse;
        }
        
        //
        // Get response.
        //
        if( rval == TSS2_RC_SUCCESS )
        {
            // Receive response from TPM.
            rval = (((TSS2_TCTI_CONTEXT_COMMON_CURRENT *)downstreamTctiContext)->receive) (
                    (TSS2_TCTI_CONTEXT *)downstreamTctiContext,
                    (size_t *)response_size, response_buffer, timeout );

            if( rval == TSS2_RC_SUCCESS )
            {
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent = 0;
                ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->currentTctiContext = 0;
            }
            else
            {
                goto returnFromResourceMgrReceiveTpmResponse;
            }
        }

        if( *response_size == 0 )
        {
            rval = TSS2_TCTI_RC_IO_ERROR;
            goto returnFromResourceMgrReceiveTpmResponse;
        }
        
        if( rmCommandDebug == 1 )
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;
        }
        else
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_DISABLED;
        }

        rmDebugPrefix = 1;

        if( rval == TSS2_RC_SUCCESS )
        {
            TPM_HANDLE realHandle;
            UINT8 objectContextLoad = 0;
            UINT8 sessionContextLoad = 0;
            
            //
            // Command passed, so do resource manager things.
            //
            RESMGR_UNMARSHAL_UINT16( response_buffer, *response_size, &currentPtr, &tag, &responseRval, returnFromResourceMgrReceiveTpmResponse );

            // Skip response size.
            RESMGR_UNMARSHAL_UINT32( response_buffer, *response_size, &currentPtr, 0, &responseRval, returnFromResourceMgrReceiveTpmResponse );

            // Get response code.
            RESMGR_UNMARSHAL_UINT32( response_buffer, *response_size, &currentPtr, &responseCode, &responseRval, returnFromResourceMgrReceiveTpmResponse );

            if( responseCode == TSS2_RC_SUCCESS )
            {
                commandPassed = 1;
                numResponseHandles = GetNumRspHandles( currentCommandCode, supportedCommands );

                if( numResponseHandles )
                {
                    // Get response handles
                    for( i = 0; i < numResponseHandles; i++ )
                    {
                        RESMGR_UNMARSHAL_UINT32( response_buffer, *response_size, &currentPtr, &(responseHandles[i]), &responseRval, returnFromResourceMgrReceiveTpmResponse );
                    }

                    // If ContextLoad command and returned handle isn't a session handle,
                    // then we need to handle it like a newly created object or sequence.
                    if( currentCommandCode == TPM_CC_ContextLoad )
                    {
                        realHandle = responseHandles[0];

                        if( !IsSessionHandle( realHandle ) )
                        {
                            objectContextLoad = 1;
                        }
                        else
                        {
                            sessionContextLoad = 1;
                        }
                    }
                }

                // Save currentPtr so we can go back later.
                savedCurrentPtr = currentPtr;


                if( currentCommandCode == TPM_CC_CreatePrimary ||
                        currentCommandCode == TPM_CC_Load ||
                        currentCommandCode == TPM_CC_LoadExternal ||
                        currentCommandCode == TPM_CC_HMAC_Start ||
                        currentCommandCode == TPM_CC_HashSequenceStart ||
                        currentCommandCode == TPM_CC_StartAuthSession ||
                        objectContextLoad || sessionContextLoad )
                {
                    TPM_HANDLE newVirtualHandle;

                    realHandle = responseHandles[0];

                    if( currentCommandCode == TPM_CC_StartAuthSession || sessionContextLoad )
                    {
                        newVirtualHandle = realHandle;

                        if( currentCommandCode == TPM_CC_StartAuthSession )
                        {
                            // Adjust session count.
                            activeSessionCount++;
                        }
                    }

                    responseRval = GetNewVirtualHandle( realHandle, &newVirtualHandle );
                    if( responseRval != TSS2_RC_SUCCESS )
                    {
                        goto returnFromResourceMgrReceiveTpmResponse;
                    }

                    if( !sessionContextLoad )
                    {
                        UINT8 *responseHandlePtr = &( ( (TPM20_Header_Out *)response_buffer )->otherData );
                        
                        responseRval = AddEntry( newVirtualHandle, realHandle, cmdParentHandle, cmdHierarchy, cmdConnectionId );
                        if( responseRval != TSS2_RC_SUCCESS )
                        {
                            goto returnFromResourceMgrReceiveTpmResponse;
                        }

                        // Replace real handle with virtual handle in response byte stream.
                        *( (TPM_HANDLE *) responseHandlePtr ) = 
                                CHANGE_ENDIAN_DWORD( newVirtualHandle );

                        if( objectContextLoad )
                        {
                            // Update context in RM entry.
                            responseRval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, newVirtualHandle, &foundEntryPtr);
                            if( responseRval != TSS2_RC_SUCCESS )
                            {
                                goto returnFromResourceMgrReceiveTpmResponse;
                            }

                            foundEntryPtr->context = cmdObjectContext;
                        }
                    }

                    responseRval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, newVirtualHandle, &foundEntryPtr);
                    if( responseRval != TSS2_RC_SUCCESS )
                    {
                        goto returnFromResourceMgrReceiveTpmResponse;
                    }

                    if( sessionContextLoad )
                    {
                        //
                        // Update loaded bit so that EvictEntities function that is called at the
                        // the end of ResourceMgrReceiveTpmResponse will work.
                        //
                        // For objects and sequences this happens during AddEntry, but
                        // not for sessions.  So we have to do it here.
                        //
                        foundEntryPtr->status.loaded = 1;
                    }
                    else
                    {

                        if( currentCommandCode == TPM_CC_CreatePrimary ||
                                currentCommandCode == TPM_CC_Load ||
                                currentCommandCode == TPM_CC_LoadExternal )
                        {
                            if( cmdStClearBit )
                            {
                                foundEntryPtr->status.stClear = 1;
                            }
                        }
                    }
                }
                else if( currentCommandCode == TPM_CC_ContextSave && IsSessionHandle( cmdSavedHandle ) )
                {
                    responseRval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, cmdSavedHandle, &foundEntryPtr);
                    if( responseRval != TSS2_RC_SUCCESS )
                    {
                        goto returnFromResourceMgrReceiveTpmResponse;
                    }

                    foundEntryPtr->status.loaded = 0;

                    RESMGR_UNMARSHAL_TPMS_CONTEXT( response_buffer, *response_size, &currentPtr, &( foundEntryPtr->context ), &responseRval, returnFromResourceMgrReceiveTpmResponse );
                }
                else if( currentCommandCode == TPM_CC_FlushContext )
                {
                    responseRval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, cmdFlushedHandle, &foundEntryPtr);
                    if( responseRval != TSS2_RC_SUCCESS )
                    {
                        goto returnFromResourceMgrReceiveTpmResponse;
                    }

                    responseRval = RemoveEntry( foundEntryPtr );
                    if( responseRval != TSS2_RC_SUCCESS )
                    {
                        goto returnFromResourceMgrReceiveTpmResponse;
                    }

                    if( IsSessionHandle( cmdFlushedHandle ) )
                    {
                        // Adjust session count.
                        activeSessionCount--;
                    }
                }
                else if( currentCommandCode == TPM_CC_Clear )
                {
                    // Free all VIRTUAL_HANDLE and HANDLE_STATUS structs that
                    // correspond to objects in the storage hierarchy.
                    ClearHierarchy( TPM_RH_OWNER );
                    ClearHierarchy( TPM_RH_ENDORSEMENT );
                }
                else if( currentCommandCode == TPM_CC_ChangePPS )
                {
                    // Free all VIRTUAL_HANDLE and HANDLE_STATUS structs that
                    // correspond to objects in the platform hierarchy.
                    ClearHierarchy( TPM_RH_PLATFORM );
                }
                else if( currentCommandCode == TPM_CC_ChangeEPS )
                {
                    // Free all VIRTUAL_HANDLE and HANDLE_STATUS structs that
                    // correspond to objects in the endorsement hierarchy.
                    ClearHierarchy( TPM_RH_ENDORSEMENT );
                }
                else if( currentCommandCode == TPM_CC_Shutdown )
                {
                    // Save type of shutdown.
                    if( shutdownType == TPM_SU_STATE )
                        shutdown_state = 1;
                }
                else if( currentCommandCode == TPM_CC_Startup )
                {
                    // If a startup command has occured, all transient objects and sessions
                    // are evicted.  And in some cases, some or all object contexts may be
                    // invalidated.  Need to update resource manager structures properly for
                    // all these cases.

                    // TBD:  need to add tests for all of this code.

                    UINT8 shutdownStartupSequence = TPM_RESET;
                    RESOURCE_MANAGER_ENTRY *entryPtr;

                    if( shutdown_state )
                    {
                        if( startupType == TPM_SU_CLEAR )
                            shutdownStartupSequence  = TPM_RESTART;
                        else if( startupType == TPM_SU_STATE  )
                            shutdownStartupSequence  = TPM_RESUME;
                    }

                    if( shutdownStartupSequence == TPM_RESET )
                    {
                        // Remove all TAB/RM entries.
                        entryList = 0;
                    }
                    else if( shutdownStartupSequence == TPM_RESTART )
                    {
                        //
                        // TBD:  need to beef this up for properly handling
                        // objects with stClear attribute.  Such objects will have
                        // their contexts invalidated.
                        //
                        for( i = 0, entryPtr = entryList; entryPtr != 0; entryPtr = entryPtr->nextEntry )
                        {
                            if( entryPtr->status.stClear )
                            {
                                RemoveEntry( entryPtr );
                            }
                        }
                    }
                    // Clear shutdown_state;
                    shutdown_state = 0;
                }
                else if( currentCommandCode == TPM_CC_EvictControl )
                {
                    RESOURCE_MANAGER_ENTRY *foundEntryPtr;
                    
                    if( 0 == PersistentHandle( objectHandle ) )
                    {
                        // Find entry for transient object.
                        rval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE, objectHandle, &foundEntryPtr );
                        if( rval != TSS2_RC_SUCCESS )
                            goto returnFromResourceMgrReceiveTpmResponse;

                        //
                        // Need to add entry to RM table for persistent copy.
                        //
                        // NOTE: I set the virtual handle to the persistent handle so that
                        // all the calls that look for entries based on the virtual handle can
                        // stay the same.
                        //
                        rval = AddEntry( persistentHandle, persistentHandle, foundEntryPtr->parentHandle,
                                foundEntryPtr->hierarchy, cmdConnectionId );
                        if( rval != TSS2_RC_SUCCESS )
                            goto returnFromResourceMgrReceiveTpmResponse;
                    }
                    else
                    {
                        // Find entry for persistent object.
                        rval = FindEntry( entryList, RMFIND_REAL_HANDLE, persistentHandle, &foundEntryPtr );
                        if( rval != TSS2_RC_SUCCESS )
                            goto returnFromResourceMgrReceiveTpmResponse;
                            
                        // Need to remove RM entry for persistent copy.
                        rval = RemoveEntry( foundEntryPtr );
                        if( rval != TSS2_RC_SUCCESS )
                            goto returnFromResourceMgrReceiveTpmResponse;
                    }
                }

                // Now do actions related to the commands's sessions.

                // First check tag to see if any sessions are present.

                if( tag == TPM_ST_SESSIONS )
                {
                    UINT32 parametersSize;
                    
                    currentPtr = savedCurrentPtr;
                    
                    // Skip past parameters area
                    RESMGR_UNMARSHAL_UINT32( response_buffer, *response_size, &currentPtr, &parametersSize, &responseRval, returnFromResourceMgrReceiveTpmResponse );
                    currentPtr += parametersSize;

                    // Check that we won't run off end of buffer when we get authorizations.
                    responseRval = CheckOverflow( response_buffer, *response_size, currentPtr, 0 );
                    if( responseRval != TSS2_RC_SUCCESS )
                    {
                        goto returnFromResourceMgrReceiveTpmResponse;
                    }
                    
                    endAuth = response_buffer + *response_size;

                    // Check that we won't run off end of buffer when we get authorizations.
                    responseRval = CheckOverflow( response_buffer, *response_size, endAuth, 0 );
                    if( responseRval != TSS2_RC_SUCCESS )
                    {
                        goto returnFromResourceMgrReceiveTpmResponse;
                    }
                    
                    // Now walk through sessions and do actions.
                    for( i = 0; currentPtr < endAuth; i++ )
                    {
                        // Skip past nonce.
                        RESMGR_UNMARSHAL_SIMPLE_TPM2B( response_buffer, *response_size, &currentPtr, 0, &responseRval, returnFromResourceMgrReceiveTpmResponse );

                        RESMGR_UNMARSHAL_UINT8( response_buffer, *response_size, &currentPtr, (UINT8 *)&sessionAttributes, &responseRval, returnFromResourceMgrReceiveTpmResponse );
                        
                        if( HandleWeCareAbout( sessionHandles[i].sessionHandle ) )
                        {
                            if( sessionAttributes.continueSession != sessionHandles[i].sessionAttributes.continueSession )
                                responseRval = TSS2_RESMGR_CONTINUE_BIT_MISMATCH;

                            if( responseRval != TSS2_RC_SUCCESS )
                                goto returnFromResourceMgrReceiveTpmResponse;   

                            responseRval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE,
                                    sessionHandles[i].sessionHandle, &foundEntryPtr);
                            if( responseRval != TSS2_RC_SUCCESS )
                            {
                                goto returnFromResourceMgrReceiveTpmResponse;
                            }

                            if( sessionAttributes.continueSession != 1 )
                            {
                                // Session ended, so remove it's entry.
                                (void) RemoveEntry( foundEntryPtr );

                                // Adjust session count.
                                activeSessionCount--;
                            }
                            else
                            {
                                // Evict session.
                                responseRval = EvictContext( foundEntryPtr->virtualHandle );
                                if( responseRval != TSS2_RC_SUCCESS )
                                {
                                    goto returnFromResourceMgrReceiveTpmResponse;
                                }
                            }
                        }

                        // Skip past auth.
                        RESMGR_UNMARSHAL_SIMPLE_TPM2B( response_buffer, *response_size, &currentPtr, 0, &responseRval, returnFromResourceMgrReceiveTpmResponse );
                    }
                }
            }
        }
    }

returnFromResourceMgrReceiveTpmResponse:

    if( !commandPassed || (responseRval != TSS2_RC_SUCCESS ) )
    {
        // Still need to evict sessions, but can only use the session handles known
        // at the time command was sent.
        // And no sessions are terminated.
        for( i = 0; i < numSessionHandles; i++ )
        {
            if( HandleWeCareAbout( sessionHandles[i].sessionHandle ) )
            {
                returnResponseRval = FindEntry( entryList, RMFIND_VIRTUAL_HANDLE,
                        sessionHandles[i].sessionHandle, &foundEntryPtr);
                if( returnResponseRval != TSS2_RC_SUCCESS )
                {
                    goto exitResourceMgrReceiveTpmResponse;
                }
                // Evict session.
                returnResponseRval = EvictContext( foundEntryPtr->virtualHandle );
                if( returnResponseRval != TSS2_RC_SUCCESS )
                {
                    goto exitResourceMgrReceiveTpmResponse;
                }
            }
        }
    }
    
    // Now evict the objects, sequences, and sessions used in handles area by the command.
    // If command was FlushContext, the entry was already removed from the list.  No eviction
    // necsssary or possible (because no entry exists for this object or sequence anymore).
    if( numHandles &&
            !( currentCommandCode == TPM_CC_ContextSave &&
                IsSessionHandle( cmdSavedHandle ) ) &&
            ( currentCommandCode != TPM_CC_FlushContext ) )
    {
        // Create array of handles.
        TPM_HANDLE usedHandles[3];
        int i;
        
        for( i = 0; i < numHandles; i++ )
        {
            usedHandles[i] = cmdHandles[i].handle;
        }
        
        returnResponseRval = EvictEntities( numHandles, &usedHandles[0] );

        if( returnResponseRval != TSS2_RC_SUCCESS )
        {
            goto exitResourceMgrReceiveTpmResponse;
        }
    }

    if( responseCode == TSS2_RC_SUCCESS )
    {
        // Now evict objects, sequences, and sessions corresponding to returned handles.
        TPM_HANDLE returnedHandles[3], *rspHandles;
        int i;

        // Create a list of virtual handles correpsponding to the real handles returned.
        rspHandles = (TPM_HANDLE *)&( ( (TPM20_Header_Out *)response_buffer )->otherData );
        
        for( i = 0; i < numResponseHandles; i++ )
        {
            returnedHandles[i] = CHANGE_ENDIAN_DWORD( rspHandles[i] );
        }

        // Now evict the entities corresponding to the virtualized returned handles.
        returnResponseRval = EvictEntities( numResponseHandles, &returnedHandles[0] );
    }

exitResourceMgrReceiveTpmResponse:

    // Preserve first error that occurs. Only return error that occurred during
    // exiting if no previous error occurred
    if( responseRval == TSS2_RC_SUCCESS )
        responseRval = returnResponseRval;

    
    PrintRMTables();

    testForLoadedSessionsOrObjectsRval = TestForLoadedHandles();

    if( responseRval == TSS2_RC_SUCCESS )
        responseRval = testForLoadedSessionsOrObjectsRval;
    
    if( responseRval != TSS2_RC_SUCCESS )
    {
        // If RM internal error or error from layers below RM occurred,
        // create an error response byte stream and return it.
        CreateErrorResponse( responseRval );
        CopyErrorResponse( response_size, response_buffer );
    }

    ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;
    
    rmDebugPrefix = 0;


    return rval;
}

typedef UINT8 (*SERVER_FN)(void *serverStruct);

typedef struct serverStruct
{
    SOCKET connectSock;
    SERVER_FN serverFn;
    char *serverName;
    THREAD_TYPE threadHandle;
} SERVER_STRUCT;
    
UINT8 TpmCmdServer( SERVER_STRUCT *serverStruct )
{
    UINT32 numBytes, sendCmd, trash = 0;
    UINT8 locality, statusBits, debugLevel;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    UINT8 returnValue = 0;
    fd_set readFds;
    int iResult;

    for(;;)
    {
        FD_ZERO( &readFds );
        FD_SET( serverStruct->connectSock, &readFds );

        iResult = select( serverStruct->connectSock+1, &readFds, 0, 0, 0 );
        if( iResult == 0 )
        {
            ResMgrPrintf( NO_PREFIX, "select failed due to timeout, socket #: 0x%x\n", serverStruct->connectSock );
            rval = TSS2_TCTI_RC_TRY_AGAIN;
        }
        else if( iResult == SOCKET_ERROR )
        {
            ResMgrPrintf( NO_PREFIX, "select failed with socket error: %d\n", WSAGetLastError() );
            rval = TSS2_TCTI_RC_IO_ERROR;
        }
        else if ( iResult != 1 )
        {
            ResMgrPrintf( NO_PREFIX, "select failed, read the wrong # of bytes: %d\n", iResult );
            rval = TSS2_TCTI_RC_IO_ERROR;
        }
        else
        {
//            ResMgrPrintf( NO_PREFIX,  "select passed on socket #0x%x\n", serverStruct->connectSock );
        }
        
        // Receive TPM Send or SESSION end command
        rval = recvBytes( serverStruct->connectSock, (unsigned char*) &sendCmd, 4 );
        if( rval != TSS2_RC_SUCCESS )
        {
            returnValue = 1;
            goto tpmCmdDone;
        }
                 
        sendCmd = CHANGE_ENDIAN_DWORD( sendCmd );

        if( sendCmd == TPM_SESSION_END )
        {
            returnValue = 1;
        }
        else if( sendCmd != MS_SIM_TPM_SEND_COMMAND )
        {
            returnValue = 1;
        }
        else
        {

            // Receive the locality.
            rval = recvBytes( serverStruct->connectSock, (unsigned char*) &locality, 1 );
            if( rval != TSS2_RC_SUCCESS )
            {
                CreateErrorResponse( TSS2_TCTI_RC_IO_ERROR );
                SendErrorResponse( serverStruct->connectSock ); 
                continue;
            }
            (( TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.locality = locality;

            // Receive debug level.
            rval = recvBytes( serverStruct->connectSock, (unsigned char*) &debugLevel, 1 );
            if( rval != TSS2_RC_SUCCESS )
            {
                CreateErrorResponse( TSS2_TCTI_RC_IO_ERROR );
                SendErrorResponse( serverStruct->connectSock ); 
                continue;
            }
            SetDebug( debugLevel );

            // Receive status bits.
            rval = recvBytes( serverStruct->connectSock, (unsigned char*) &statusBits, 1 );
            if( rval != TSS2_RC_SUCCESS )
            {
                CreateErrorResponse( TSS2_TCTI_RC_IO_ERROR );
                SendErrorResponse( serverStruct->connectSock ); 
                continue;
            }
            (( TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.commandSent = statusBits & 0x1;
            (( TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.rmDebugPrefix = 0;

            // Receive number of bytes.
            rval = recvBytes( serverStruct->connectSock, (unsigned char*) &numBytes, 4);
            if( rval != TSS2_RC_SUCCESS )
            {
                CreateErrorResponse( TSS2_TCTI_RC_IO_ERROR );
                SendErrorResponse( serverStruct->connectSock ); 
                continue;
            }

            numBytes = CHANGE_ENDIAN_DWORD( numBytes );

            // Receive the TPM command bytes from calling application.
            rval = recvBytes( serverStruct->connectSock, (unsigned char *)cmdBuffer, numBytes);
            if( rval != TSS2_RC_SUCCESS )
            {
                CreateErrorResponse( TSS2_TCTI_RC_IO_ERROR );
                SendErrorResponse( serverStruct->connectSock ); 
                continue;
            }

            // Send TPM command to TPM.
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext)->currentConnectSock = serverStruct->connectSock;
            rval = ResourceMgrSendTpmCommand( downstreamTctiContext, numBytes, cmdBuffer );
            if( rval != TSS2_RC_SUCCESS )
            {
                CreateErrorResponse( TSS2_TCTI_RC_IO_ERROR );
                SendErrorResponse( serverStruct->connectSock ); 
                continue;
            }

            // Receive response from TPM.
            numBytes = maxRspSize;
            rval = ResourceMgrReceiveTpmResponse( downstreamTctiContext, &numBytes, rspBuffer, TSS2_TCTI_TIMEOUT_BLOCK );
            if( rval != TSS2_RC_SUCCESS )
            {
                CreateErrorResponse( TSS2_TCTI_RC_IO_ERROR );
                SendErrorResponse( serverStruct->connectSock ); 
                continue;
            }

            numBytes = CHANGE_ENDIAN_DWORD( numBytes );

            // Send size of TPM response to calling application.        
            rval = sendBytes( serverStruct->connectSock, (char *)&numBytes, 4 );
            if( rval != TSS2_RC_SUCCESS )
            {
                returnValue = 1;
                goto tpmCmdDone;
            }

            numBytes = CHANGE_ENDIAN_DWORD( numBytes );

            // Send TPM or RM response to calling application.        
            rval = sendBytes( serverStruct->connectSock, (char *)rspBuffer, numBytes );
            if( rval != TSS2_RC_SUCCESS )
            {
                returnValue = 1;
                goto tpmCmdDone;
            }

            // Send the appended four bytes of 0's
            sendBytes( serverStruct->connectSock, (char *)&trash, 4 );        
            if( rval != TSS2_RC_SUCCESS )
            {
                returnValue = 1;
                goto tpmCmdDone;
            }
        }
        if( returnValue == 1 )
            break;
        
    }


tpmCmdDone:

    printf( "TpmCmdServer died (%s), rval: 0x%8.8x, socket: 0x%x.\n", serverStruct->serverName, rval, serverStruct->connectSock );

    closesocket( serverStruct->connectSock );
	CloseHandle( serverStruct->threadHandle );
    (*rmFree)( serverStruct );
	ExitThread( 0 );

	return returnValue;
}

TSS2_RC ResourceMgrSetLocality(
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t         locality     /* in */
    )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;

    if( tctiContext == 0 )
    {
        rval = TSS2_TCTI_RC_BAD_REFERENCE;
    }
    else if( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality != locality )
    {
        if ( ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.commandSent == 1 )
        {
            rval = TSS2_TCTI_RC_BAD_SEQUENCE;
        }
        else
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)tctiContext)->status.locality = locality;
        }
    }

    return rval;
}

UINT8 OtherCmdServer( SERVER_STRUCT *serverStruct )
{
    UINT32 command;
    UINT8 returnValue = 0;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    fd_set readFds;
    int iResult;
    
     for(;;)
    {
        FD_ZERO( &readFds );
        FD_SET( serverStruct->connectSock, &readFds );

        iResult = select( serverStruct->connectSock+1, &readFds, 0, 0, 0 );
        if( iResult == 0 )
        {
            ResMgrPrintf( NO_PREFIX,  "select failed due to timeout, socket #: 0x%x\n", serverStruct->connectSock );
            rval = TSS2_TCTI_RC_TRY_AGAIN;
            goto retOtherCmdServer;
        }
        else if( iResult == SOCKET_ERROR )
        {
            ResMgrPrintf( NO_PREFIX, "select failed with socket error: %d\n", WSAGetLastError() );
            rval = TSS2_TCTI_RC_IO_ERROR;
            goto retOtherCmdServer;
        }
        else if ( iResult != 1 )
        {
            ResMgrPrintf( NO_PREFIX, "select failed, read the wrong # of bytes: %d\n", iResult );
            rval = TSS2_TCTI_RC_IO_ERROR;
            goto retOtherCmdServer;
        }

        rval = recvBytes( serverStruct->connectSock, (unsigned char*) &command, 4);

        if( rval != TSS2_RC_SUCCESS )
        {
            goto retOtherCmdServer;
        }
        
        command = CHANGE_ENDIAN_DWORD( command );
        switch( command )
        {
            case MS_SIM_POWER_ON:
                rval = PlatformCommand( downstreamTctiContext, MS_SIM_POWER_ON );
                break;
            case MS_SIM_POWER_OFF:
                rval = PlatformCommand( downstreamTctiContext, MS_SIM_POWER_OFF );
                break;
            case MS_SIM_CANCEL_ON:
                rval = PlatformCommand( downstreamTctiContext, MS_SIM_CANCEL_ON );
                break;
            case MS_SIM_CANCEL_OFF:
                rval = PlatformCommand( downstreamTctiContext, MS_SIM_CANCEL_OFF );
                break;
            case MS_SIM_NV_ON:
                rval = PlatformCommand( downstreamTctiContext, MS_SIM_NV_ON );
                break;
            case TPM_SESSION_END:
                returnValue = 1;
                break;
            default:
                rval = TSS2_TCTI_RC_NOT_SUPPORTED;
                returnValue = 1;
        }

        if( returnValue == 0 )
        {
            rval = CHANGE_ENDIAN_DWORD( rval );

            sendBytes( serverStruct->connectSock, (char *)&rval, 4 );
        }
        else
        {
            break;
        }
    }

retOtherCmdServer:
     
    printf( "OtherCmdServer died (%s), socket: 0x%x.\n", serverStruct->serverName, serverStruct->connectSock );

    closesocket( serverStruct->connectSock );
    CloseHandle( serverStruct->threadHandle );
   (*rmFree)( serverStruct );
    ExitThread( 0 );
    
    return returnValue;
}


UINT32 WINAPI SockServer( LPVOID servStruct )
{
    UINT8 continueServer = 1;
    SERVER_STRUCT *serverStruct = (SERVER_STRUCT *)servStruct;
    SERVER_STRUCT *cmdServerStruct;
#ifdef  _WIN32
    // do nothing.
#elif __linux || __unix
    
    int rval = 0;
#endif    
    printf( "Starting SockServer (%s), socket: 0x%x.\n", serverStruct->serverName, serverStruct->connectSock );
    
    do
    {
        cmdServerStruct = (*rmMalloc)( sizeof( SERVER_STRUCT ) );
        if( cmdServerStruct == 0 )
        {
            continue;
        }

        cmdServerStruct->connectSock = accept( serverStruct->connectSock, 0, 0 );

        if( cmdServerStruct->connectSock == INVALID_SOCKET )
        {
            printf( "Accept failed.  Error is 0x%x\n", WSAGetLastError() );
            continue;
        }

        printf( "Accept socket:  0x%x\n", cmdServerStruct->connectSock );

        cmdServerStruct->serverFn = serverStruct->serverFn;
        cmdServerStruct->serverName = serverStruct->serverName;

        printf( "Resource Manager %s Server accepted client\n", serverStruct->serverName );

#ifdef  _WIN32
        cmdServerStruct->threadHandle = CreateThread( NULL, 0,
                (LPTHREAD_START_ROUTINE)serverStruct->serverFn,
                (LPVOID)cmdServerStruct, 0, NULL );
        if( cmdServerStruct->threadHandle == NULL )
        {
            closesocket( cmdServerStruct->connectSock );
            (*rmFree)( cmdServerStruct );
            printf( "Resource Mgr failed to create OTHER command server thread.  Exiting...\n" );
            continue;
        }
#elif __linux || __unix
        rval = pthread_create( &cmdServerStruct->threadHandle, 0, (void *)serverStruct->serverFn, cmdServerStruct );
        if( rval != 0 )
        {
            closesocket( cmdServerStruct->connectSock );
            (*rmFree)( cmdServerStruct );
            printf( "Resource Mgr failed to create OTHER command server thread, error #%d.  Exiting...\n", rval );
            continue;
        }
#else
#error Unsupported OS--need to add OS-specific support for threading here.        
#endif
    }
    while( continueServer );

    if( 0 == strcmp( &otherCmdStr[0], serverStruct->serverName ) )
    {
        printf( "SockServer died (%s), socket: 0x%x.\n", serverStruct->serverName, serverStruct->connectSock );
        ExitThread( 0 );
    }
    
    return continueServer;
}

#define interfaceConfigSize 250

const char *resDeviceTctiName = "device TCTI";
const char *resSocketTctiName = "socket TCTI";
TCTI_SOCKET_CONF simInterfaceConfig = {
    DEFAULT_HOSTNAME,
    DEFAULT_RESMGR_TPM_PORT
};

SOCKET simOtherSock;
SOCKET simTpmSock;

TSS2_RC InitSimulatorTctiContext( TCTI_SOCKET_CONF *tcti_conf, TSS2_TCTI_CONTEXT **tctiContext )
{
    size_t size;
    
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = InitSocketTcti(NULL, &size, tcti_conf, 0, 0, resSocketTctiName, 1 );
    if( rval != TSS2_RC_SUCCESS )
        return rval;
    
    *tctiContext = malloc(size);

    rval = InitSocketTcti(*tctiContext, &size, tcti_conf, TCTI_MAGIC, TCTI_VERSION, resSocketTctiName, 0 );
    return rval;
}

TSS2_RC InitResourceMgr( int debugLevel)
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPMS_CAPABILITY_DATA capabilityData;
    int i;
    
    SetDebug( DBG_COMMAND_RM_TABLES );

    ResMgrPrintf( NO_PREFIX, "Initializing Resource Manager\n" );

    commandDebug = 0;
    rmCommandDebug = 0;
    printRMTables = 0;

    SetDebug( debugLevel );
    
    // Now do some resource manager initialization.
    // Init entry list.
    entryList = 0;

    // Initialize freed handle arrays.
    for( i = 0; i < FREED_HANDLE_ARRAY_SIZE; i++ )
    {
        freedSessionHandles[i] = freedObjectHandles[i] = UNAVAILABLE_FREED_HANDLE;
    }

    rval = PlatformCommand( downstreamTctiContext, MS_SIM_POWER_ON );
    if( rval != TPM_RC_SUCCESS )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }
    
    rval = PlatformCommand( downstreamTctiContext, MS_SIM_NV_ON );
    if( rval != TPM_RC_SUCCESS )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }
    
    // This one should pass.
    rval = Tss2_Sys_Startup( resMgrSysContext, TPM_SU_CLEAR );
    if( rval != TPM_RC_SUCCESS && rval != TPM_RC_INITIALIZE )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }

    // Need to get some capabilities.
    
    // Get max command size.
    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_COMMAND_SIZE,
            1, 0, &capabilityData, 0 );

    if( rval != TPM_RC_SUCCESS )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }

    if( capabilityData.data.tpmProperties.count == 1 && 
            (capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_MAX_COMMAND_SIZE) )
    {
        maxCmdSize = capabilityData.data.tpmProperties.tpmProperty[0].value;
    }
    else
    {
        rval = TSS2_SIMULATOR_INTERFACE_INIT_FAILED;
        goto returnFromInitResourceMgr;
    }

    // Get max response size.
    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_RESPONSE_SIZE,
            1, 0, &capabilityData, 0 );

    if( rval != TPM_RC_SUCCESS )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }

    if( capabilityData.data.tpmProperties.count == 1 && 
            (capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_MAX_RESPONSE_SIZE) )
    {
        maxRspSize = capabilityData.data.tpmProperties.tpmProperty[0].value;
    }
    else
    {
        rval = TSS2_SIMULATOR_INTERFACE_INIT_FAILED;
        goto returnFromInitResourceMgr;
    }

    // Get max active sessions.
    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_ACTIVE_SESSIONS_MAX,
            1, 0, &capabilityData, 0 );

    if( rval != TPM_RC_SUCCESS )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }

    if( capabilityData.data.tpmProperties.count == 1 && 
            (capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_ACTIVE_SESSIONS_MAX) )
    {
        maxActiveSessions = capabilityData.data.tpmProperties.tpmProperty[0].value;
    }
    else
    {
        rval = TSS2_SIMULATOR_INTERFACE_INIT_FAILED;
        goto returnFromInitResourceMgr;
    }

    // Get max loaded sessions.
    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_HR_LOADED,
            1, 0, &capabilityData, 0 );
    if( rval != TPM_RC_SUCCESS )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }

    if( capabilityData.data.tpmProperties.count == 1 && 
            (capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_HR_LOADED) )
    {
#ifndef DEBUG_GAP_HANDLING        
        maxActiveSessions += capabilityData.data.tpmProperties.tpmProperty[0].value;
#else
        maxActiveSessions = DEBUG_MAX_ACTIVE_SESSIONS;
#endif
        ResMgrPrintf( NO_PREFIX, "maxActiveSessions = %d\n", maxActiveSessions );
    }
    else
    {
        rval = TSS2_SIMULATOR_INTERFACE_INIT_FAILED;
        goto returnFromInitResourceMgr;
    }

    // Get gap value for sessions.
    rval = Tss2_Sys_GetCapability( resMgrSysContext, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_CONTEXT_GAP_MAX,
            1, 0, &capabilityData, 0 );
    if( rval != TPM_RC_SUCCESS )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }

    if( capabilityData.data.tpmProperties.count == 1 && 
            (capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_CONTEXT_GAP_MAX))
    {
#ifndef DEBUG_GAP_HANDLING        
        gapMaxValue = capabilityData.data.tpmProperties.tpmProperty[0].value;
#else
        gapMaxValue = DEBUG_GAP_MAX;
#endif        
        ResMgrPrintf( NO_PREFIX, "gapMaxValue = %d\n", gapMaxValue );
    }
    else
    {
        rval = TSS2_SIMULATOR_INTERFACE_INIT_FAILED;
        goto returnFromInitResourceMgr;
    }

    // Get the TPM 2.0 commands supported by the TPM.
    rval = GetCommands( resMgrSysContext, &supportedCommands );
    if( rval != TPM_RC_SUCCESS )
    {
        SetRmErrorLevel( &rval, TSS2_RESMGR_ERROR_LEVEL );
        goto returnFromInitResourceMgr;
    }
    
    // Allocate memory for command/response buffers.
    cmdBuffer = (*rmMalloc)( maxCmdSize );
    if( cmdBuffer == 0 )
        return TSS2_RESMGR_MEMALLOC_FAILED;

    rspBuffer = (*rmMalloc)( maxRspSize );
    if( rspBuffer == 0 )
        return TSS2_RESMGR_MEMALLOC_FAILED;

    // Init some other state.
    lastSessionSequenceNum = 0xffffffffffffffff;
    gapMsbBitMask = (gapMaxValue + 1) >> 1;
    activeSessionCount = 0;
    
returnFromInitResourceMgr:

    SetDebug( DBG_NO_COMMAND );
    
    return rval;
}

char version[] = "0.85";

void PrintHelp()
{
    printf( "Resource manager daemon, Version %s\nUsage:  resourcemgr "
#if __linux || __unix
            "[-sim] "
#endif            
            "[-tpmhost hostname|ip_addr] [-tpmport port] [-apport port]\n"
            "\n"
            "where:\n"
            "\n"
#if __linux || __unix
            "-sim tells resource manager to communicate with TPM 2.0 simulator (default: communicates with local TPM; must be specified for running on Windows)\n"
#endif            
            "-tpmhost specifies the host IP address for communicating with the TPM (default: %s; only valid if -sim used)\n"
            "-tpmport specifies the port number for communicating with the TPM (default: %d; only valid if -sim used)\n"
            "-apport specifies the port number for communicating with the calling application (default: %d)\n"
            , version, DEFAULT_HOSTNAME, DEFAULT_SIMULATOR_TPM_PORT, DEFAULT_RESMGR_TPM_PORT );
}

void InitSysContextFailure()
{
    ResMgrPrintf( NO_PREFIX,  "In Resource Manager;  InitSysContext failed, exiting...\n" );
}

int main(int argc, char* argv[])
{
    char appHostName[200] = DEFAULT_HOSTNAME;
    uint16_t appPort = DEFAULT_RESMGR_TPM_PORT;
    int count;
    TSS2_RC rval = 0;
    SOCKET appOtherSock = 0, appTpmSock = 0;
    SERVER_STRUCT otherCmdServerStruct = { 0, (SERVER_FN)&OtherCmdServer, &otherCmdStr[0] };
    SERVER_STRUCT tpmCmdServerStruct = { 0, (SERVER_FN)&TpmCmdServer, "TPM CMD" };
    THREAD_TYPE sockServerThread;
    UINT8 tpmHostNameSpecified = 0, tpmPortSpecified = 0;
    
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);
    if( argc > MAX_COMMAND_LINE_ARGS )
    {
        PrintHelp();
        return 1;
    }
    else
    {
        for( count = 1; count < argc; count++ )
        {
#if __linux || __unix
            if( 0 == strcmp( argv[count], "-sim" ) )
            {
                simulator = 1;
            }
            else
#endif                
            if( 0 == strcmp( argv[count], "-tpmhost" ) )
            {
                count++;
                simInterfaceConfig.hostname = argv[count];
                if( count >= argc)
                {
                    PrintHelp();
                    return 1;
                }
                tpmHostNameSpecified = 1;
            }
            else if( 0 == strcmp( argv[count], "-tpmport" ) )
            {
                count++;
                simInterfaceConfig.port = strtoul(argv[count], NULL, 10);
                if( count >= argc )
                {
                    PrintHelp();
                    return 1;
                }
                tpmPortSpecified = 1;
            }
            else if( 0 == strcmp( argv[count], "-apport" ) )
            {
                count++;
                appPort = strtoul(argv[count], NULL, 10);
                if( count >= argc )
                {
                    PrintHelp();
                    return 1;
                }
            }
            else
            {
                PrintHelp();
                return 1;
            }
        }

#if __linux || __unix
        if( !simulator && ( tpmHostNameSpecified == 1 || tpmPortSpecified == 1 ) )
        {
            PrintHelp();
            return 1;
        }
#endif        
    }
#if __linux || __unix
    if( !simulator )
    {
        // Use device driver for local TPM.

        //
        // Init downstream interface to tpm (in this case the local TPM).
        //
        TCTI_DEVICE_CONF deviceTctiConfig = { "/dev/tpm0" };

        rval = InitDeviceTctiContext( &deviceTctiConfig, &downstreamTctiContext );
        if( rval != TSS2_RC_SUCCESS )
        {
            ResMgrPrintf( NO_PREFIX,  "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", resDeviceTctiName, rval );
            return( 1 );
        }
#ifdef DEBUG_RESMGR_INIT        
        else
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;
        }
#endif        
    }
    else
#endif        
    {
        rval = InitSimulatorTctiContext( &simInterfaceConfig, &downstreamTctiContext );
        if( rval != TSS2_RC_SUCCESS )
        {
            ResMgrPrintf( NO_PREFIX,  "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", resSocketTctiName, rval );
            return( 1 );
        }
#ifdef DEBUG_RESMGR_INIT        
        else
        {
            ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_ENABLED;
        }
#endif        
    }
    // Init sysContext for use by RM.  Used to send RM specific TPM commands to the TPM.
    resMgrSysContext = InitSysContext( 0, downstreamTctiContext, &abiVersion );
    if( resMgrSysContext == 0 )
    {
        InitSysContextFailure();
        goto initDone;
    }
    
    rval = InitResourceMgr( DBG_COMMAND_RM_TABLES );
    if( rval != TSS2_RC_SUCCESS )
    {
        printf( "Resource Mgr failed to initialize.  Exiting...\n" );
        return( 1 );
    }

    // Flush all loaded handles
    rval = FlushAllLoadedHandles();
    if( rval != TSS2_RC_SUCCESS )
    {
        printf( "Resource Mgr failed to flush all loaded handles.  Exiting...\n" );
        return( 1 );
    }

#ifdef DEBUG_RESMGR_INIT        
    ((TSS2_TCTI_CONTEXT_INTEL *)downstreamTctiContext )->status.debugMsgLevel = TSS2_TCTI_DEBUG_MSG_DISABLED;
#endif        

    if( 0 != InitSockets( appHostName, appPort, 1, &appOtherSock, &appTpmSock ) )
    {
        printf( "Resource Mgr, upstream interface to applications, failed to init sockets.  Exiting...\n" );
        closesocket( appOtherSock );
        return( 1 );
    }

    otherCmdServerStruct.connectSock = appOtherSock;
    tpmCmdServerStruct.connectSock = appTpmSock;
    
    // Start socket servers for upstream interface.

#ifdef  _WIN32
    if( NULL == ( sockServerThread = CreateThread( NULL, 0,
            (LPTHREAD_START_ROUTINE)SockServer,
            (LPVOID)&otherCmdServerStruct, 0, NULL ) ) )
    {
        printf( "Resource Mgr failed to create OTHER command server thread.  Exiting...\n" );
    }
#elif __linux || __unix
    rval = pthread_create( &sockServerThread, 0, (void *)SockServer, &otherCmdServerStruct );
    if( rval != 0 )
    {
        printf( "Resource Mgr failed to create OTHER command server thread, error #%d.  Exiting...\n", rval );
    }
#else
#error Unsupported OS--need to add OS-specific support for threading here.        
#endif        
    else
    {
        SockServer( (LPVOID)&tpmCmdServerStruct );
    }

    CloseHandle( sockServerThread );

    CloseSockets( appOtherSock, appTpmSock );
    
    TeardownSysContext( &resMgrSysContext );
    
initDone:

    return 0;
}
