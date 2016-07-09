#ifdef __cplusplus
extern "C" {
#endif

#include <sapi/tpm20.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
void WSACleanup();
#define closesocket(serverSock) close(serverSock)
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

int
InitSockets( const char *hostName,
             UINT16 port,
             UINT8 serverSockets,
             SOCKET *otherSock,
             SOCKET *tpmSock,
             TCTI_LOG_CALLBACK  logCallback,
             void *logData );
void CloseSockets( SOCKET serverSock, SOCKET tpmSock );
TSS2_RC recvBytes( SOCKET tpmSock, unsigned char *data, int len );
TSS2_RC sendBytes( SOCKET tpmSock, const unsigned char *data, int len );

#ifdef __cplusplus
}
#endif
