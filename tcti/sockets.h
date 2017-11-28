#ifdef __cplusplus
extern "C" {
#endif

#include "sapi/tpm20.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
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

#if !defined(MSG_NOSIGNAL)
# if defined(SO_NOSIGPIPE)
#   define MSG_NOSIGNAL 0
#   define TSS2_USE_SO_NOSIGPIPE
# else
#   error "Neither MSG_NOSIGNAL nor SO_NOSIGPIPE is defined."
# endif
#endif

int
InitSockets( const char *hostName,
             UINT16 port,
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
