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
TSS2_RC
socket_close (
    SOCKET *socket);
ssize_t
socket_recv_buf (
    SOCKET sock,
    unsigned char *data,
    size_t size);
TSS2_RC
socket_xmit_buf (
    SOCKET sock,
    const void *buf,
    size_t size);

#ifdef __cplusplus
}
#endif
