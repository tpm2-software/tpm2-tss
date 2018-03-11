
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "tpm20.h"

#define SOCKET int

#ifdef __cplusplus
extern "C" {
#endif

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
