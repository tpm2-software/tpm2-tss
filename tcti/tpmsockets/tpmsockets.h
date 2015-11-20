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

#ifndef TPM_SOCKETS_H
#define TPM_SOCKETS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
void WSACleanup();
#define closesocket(serverSock) close(serverSock)
#define SOCKADDR struct sockaddr
#define SOCKADDR struct sockaddr
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
int WSAGetLastError();
#define WINAPI
#define LPVOID void *
#else
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")

#include <ws2tcpip.h>

#endif


#define DEFAULT_SIMULATOR_TPM_PORT        2321
#define TSS2_SIMULATOR_INTERFACE_INIT_FAILED              ((TSS2_RC)(1 + TSS2_DRIVER_ERROR_LEVEL))

#define DEFAULT_RESMGR_TPM_PORT        2323
#define TSS2_RESMGR_INTERFACE_INIT_FAILED                 ((TSS2_RC)(1 + TSS2_TCTI_ERROR_LEVEL))

#define DEFAULT_HOSTNAME        "127.0.0.1"

#define HOSTNAME_LENGTH 200

extern TSS2_TCTI_DRIVER_INFO tpmSocketsTctiInfo;

TSS2_RC PlatformCommand(
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    char cmd );

int InitSockets( char *hostName, int port, UINT8 serverSockets, SOCKET *otherSock, SOCKET *tpmSock );

void CloseSockets( SOCKET serverSock, SOCKET tpmSock );

TSS2_RC InitSocketsTcti (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    size_t *contextSize,            // IN/OUT
    const char *config,             // IN        
    const uint64_t magic,
    const uint32_t version,
	const char *interfaceName,
    const uint8_t serverSockets
    );

TSS2_RC TeardownSocketsTcti (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    const char *config,             // IN        
	const char *interfaceName
    );

TSS2_RC recvBytes( SOCKET tpmSock, unsigned char *data, int len );

TSS2_RC sendBytes( SOCKET tpmSock, const char *data, int len );

TSS2_RC SocketSendSessionEnd( 
    TSS2_TCTI_CONTEXT *tctiContext,      
    UINT8 tpmCmdServer
    );

extern char outFileName[200];

extern UINT8 simulator;


// Commands to send to OTHER port.
#define MS_SIM_POWER_ON         1
#define MS_SIM_POWER_OFF        2
#define MS_SIM_TPM_SEND_COMMAND 8
#define MS_SIM_CANCEL_ON        9
#define MS_SIM_CANCEL_OFF       10
#define MS_SIM_NV_ON            11
#define TPM_SESSION_END         20

#ifdef __cplusplus
}
#endif

#endif


