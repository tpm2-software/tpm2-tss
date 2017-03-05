#include <unistd.h>
#include <netinet/in.h>

#include "tcti/tcti_socket.h"
#include "debug.h"
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

    for( bytesRead = 0, length = len; bytesRead != len; length -= iResult, bytesRead += iResult )
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
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC sendBytes( SOCKET tpmSock, const unsigned char *data, int len )
{
    int iResult = 0;
    int sentLength = 0;

    for( sentLength = 0; sentLength < len; len -= iResult, sentLength += iResult )
    {
        iResult = send( tpmSock, (char *)data, len, MSG_NOSIGNAL );
        if (iResult == SOCKET_ERROR)
        {
            if (wasInterrupted())
                continue;
            else
                return TSS2_TCTI_RC_IO_ERROR;
        }
    }

    return TSS2_RC_SUCCESS;
}

#define SAFE_CALL(func, ...) (func != NULL) ? func(__VA_ARGS__) : 0
int
InitSockets( const char *hostName,
             UINT16 port,
             UINT8 serverSockets,
             SOCKET *otherSock,
             SOCKET *tpmSock,
             TCTI_LOG_CALLBACK debugfunc,
             void* data )
{
    struct sockaddr_in otherService;
    struct sockaddr_in tpmService;
    int iResult = 0;            // used to return function results

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

        if( serverSockets )
        {
            // Bind the socket.
            iResult = bind(*otherSock, (SOCKADDR *) &otherService, sizeof (otherService));
            if (iResult == SOCKET_ERROR) {
                SAFE_CALL( debugfunc, data, NO_PREFIX, "bind failed with error %u\n", WSAGetLastError());
                closesocket(*otherSock);
                WSACleanup();
                return 1;
            }
            else
            {
                SAFE_CALL( debugfunc, data, NO_PREFIX, "bind to IP address:port:  %s:%d\n", hostName, port + 1 );
            }

            iResult = listen( *otherSock, 4 );
            if (iResult == SOCKET_ERROR) {
                SAFE_CALL( debugfunc, data, NO_PREFIX, "listen failed with error %u\n", WSAGetLastError());
                closesocket(*otherSock);
                WSACleanup();
                return 1;
            }
            else
            {
                SAFE_CALL( debugfunc, data, NO_PREFIX, "Other CMD server listening to socket:  0x%x\n", *otherSock );
            }
        }
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

        if( serverSockets )
        {
            // Bind the socket.
            iResult = bind(*tpmSock, (SOCKADDR *) &tpmService, sizeof (tpmService));
            if (iResult == SOCKET_ERROR) {
                SAFE_CALL( debugfunc, data, NO_PREFIX, "bind failed with error %u\n", WSAGetLastError());
                closesocket(*tpmSock);
                WSACleanup();
                return 1;
            }
            else
            {
                SAFE_CALL( debugfunc, data, NO_PREFIX, "bind to IP address:port:  %s:%d\n", hostName, port );
            }

            iResult = listen( *tpmSock, 4 );
            if (iResult == SOCKET_ERROR) {
                SAFE_CALL( debugfunc, data, NO_PREFIX, "listen failed with error %u\n", WSAGetLastError());
                closesocket(*tpmSock);
                WSACleanup();
                return 1;
            }
            else
            {
                SAFE_CALL( debugfunc, data, NO_PREFIX, "TPM CMD server listening to socket:  0x%x\n", *tpmSock );
            }
        }
    }

    if( !serverSockets )
    {
        // Connect to server.
        iResult = connect(*otherSock, (SOCKADDR *) &otherService, sizeof (otherService));
        if (iResult == SOCKET_ERROR) {
            SAFE_CALL( debugfunc, data, NO_PREFIX, "connect function failed with error: %d\n", WSAGetLastError() );
            iResult = closesocket(*otherSock);
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
    }

    return 0;
}
