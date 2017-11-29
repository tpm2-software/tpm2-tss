#include <unistd.h>
#include <netinet/in.h>

#include "tcti/tcti_socket.h"
#include "common/debug.h"
#include "sockets.h"

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

TSS2_RC sendBytes( SOCKET tpmSock, const unsigned char *data, int len )
{
    int iResult = 0;
    int sentLength = 0;

    for( sentLength = 0; sentLength < len; )
    {
        iResult = send( tpmSock, (char *)data, len, MSG_NOSIGNAL );
        if (iResult == SOCKET_ERROR)
        {
            if (wasInterrupted())
                continue;
            else
                return TSS2_TCTI_RC_IO_ERROR;
        }

        len -= iResult;
        sentLength += iResult;
    }

    return TSS2_RC_SUCCESS;
}

#define SAFE_CALL(func, ...) (func != NULL) ? func(__VA_ARGS__) : 0
int
InitSockets( const char *hostName,
             UINT16 port,
             SOCKET *otherSock,
             SOCKET *tpmSock,
             TCTI_LOG_CALLBACK debugfunc,
             void* data )
{
    struct sockaddr_in otherService = { 0 };
    struct sockaddr_in tpmService = { 0 };
    int iResult = 0;            // used to return function results
#if defined(TSS2_USE_SO_NOSIGPIPE)
    int no_sigpipe_val = 1;
#endif

    *otherSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*otherSock == INVALID_SOCKET)
    {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "socket creation failed with error = %d\n", WSAGetLastError() );
        return(1);
    }
    else {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "socket created:  0x%x\n", *otherSock );
        otherService.sin_family = AF_INET;
        otherService.sin_addr.s_addr = inet_addr( hostName );
        otherService.sin_port = htons(port + 1);
    }

    *tpmSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*tpmSock == INVALID_SOCKET)
    {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "socket creation failed with error = %d\n", WSAGetLastError() );
        closesocket( *otherSock );
        return(1);
    }
    else {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "socket created:  0x%x\n", *tpmSock );
        tpmService.sin_family = AF_INET;
        tpmService.sin_addr.s_addr = inet_addr( hostName );
        tpmService.sin_port = htons( port );

    }

#if defined(TSS2_USE_SO_NOSIGPIPE)
    iResult = setsockopt(*otherSock, SOL_SOCKET, SO_NOSIGPIPE, (void*)&no_sigpipe_val, sizeof(no_sigpipe_val));
    if (iResult)
    {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "setting SO_NOSIGPIPE failed with error = %d\n", WSAGetLastError() );
        closesocket( *otherSock );
        WSACleanup();
        return 1;
    }

    iResult = setsockopt(*tpmSock, SOL_SOCKET, SO_NOSIGPIPE, (void*)&no_sigpipe_val, sizeof(no_sigpipe_val));
    if (iResult)
    {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "setting SO_NOSIGPIPE failed with error = %d\n", WSAGetLastError() );
        closesocket( *otherSock );
        WSACleanup();
        return 1;
    }
#endif

    // Connect to server.
    iResult = connect(*otherSock, (SOCKADDR *) &otherService, sizeof (otherService));
    if (iResult == SOCKET_ERROR) {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "connect function failed with error: %d\n", WSAGetLastError() );
        closesocket(*otherSock);
        WSACleanup();
        return 1;
    }
    else
    {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "Client connected to server on port:  %d\n", port + 1 );
    }

    // Connect to server.
    iResult = connect(*tpmSock, (SOCKADDR *) &tpmService, sizeof (tpmService));
    if (iResult == SOCKET_ERROR) {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "connect function failed with error: %d\n", WSAGetLastError() );
        iResult = closesocket(*otherSock);
        if (iResult == SOCKET_ERROR)
        {
            SAFE_CALL( debugfunc, data, NO_PREFIX, "closesocket function failed with error: %d\n", WSAGetLastError() );
        }
        WSACleanup();
        return 1;
    }
    else
    {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "Client connected to server on port:  %d\n", port );
    }

    return 0;
}
