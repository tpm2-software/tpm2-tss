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

TSS2_RC
socket_connect (
    const char *hostname,
    uint16_t port,
    SOCKET *socket);
void CloseSockets( SOCKET serverSock, SOCKET tpmSock );
TSS2_RC recvBytes( SOCKET tpmSock, unsigned char *data, int len );

#ifdef __cplusplus
}
#endif
