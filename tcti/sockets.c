/*
 * Copyright (c) 2015 - 2018 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "sockets.h"
#define LOGMODULE tcti
#include "log/log.h"

void WSACleanup() {}
int WSAGetLastError() { return errno; }
int wasInterrupted() { return errno == EINTR; }

void CloseSockets( SOCKET otherSock, SOCKET tpmSock)
{
    closesocket(otherSock);
    closesocket(tpmSock);
}

TSS2_RC recvBytes( SOCKET tpmSock, unsigned char *data, int len )
{
    int iResult = 0;
    int length;
    int bytesRead;

    for( bytesRead = 0, length = len; bytesRead != len; )
    {
        iResult = recv( tpmSock, (char *)&( data[bytesRead] ), length, 0);
        if (iResult == SOCKET_ERROR)
        {
            if (wasInterrupted())
                continue;
            return TSS2_TCTI_RC_IO_ERROR;
        }
        else if (!iResult)
            return TSS2_TCTI_RC_IO_ERROR;

        length -= iResult;
        bytesRead += iResult;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
socket_connect (
    const char *hostname,
    uint16_t port,
    SOCKET *sock)
{
    struct sockaddr_in sockaddr = { 0 };
    int ret = 0;

    LOG_DEBUG ("Creating AF_INET stream socket");
    *sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*sock == -1) {
        LOG_WARNING ("Failed to create socket. errno %d: %s",
                     errno, strerror (errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr (hostname);
    sockaddr.sin_port = htons (port);

    LOG_DEBUG ("Connecting socket %d to hostname %s on port %" PRIu16,
               *sock, hostname, port);
    ret = connect (*sock, (struct sockaddr*)&sockaddr, sizeof (sockaddr));
    if (ret == -1) {
        LOG_WARNING ("Failed to connect to host %s on port %" PRIu16 ", errno "
                     "%d: %s", hostname, port, errno, strerror (errno));
        close (*sock);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}
