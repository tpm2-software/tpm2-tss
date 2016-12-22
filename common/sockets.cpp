#include <tcti/tcti_socket.h>
#include "debug.h"
#include "sockets.h"

#ifndef _WIN32
void WSACleanup() {}
int WSAGetLastError() { return errno; }
#endif

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
        if ((iResult == SOCKET_ERROR) || (!iResult))
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
            return TSS2_TCTI_RC_IO_ERROR;
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
    sockaddr_in otherService;
    sockaddr_in tpmService;
#ifndef _WIN32
    int optval = 1;
#endif
    int iResult = 0;            // used to return function results

#ifdef _WIN32
    WSADATA wsaData = {0};
    static UINT8 socketsEnabled = 0;

    if( socketsEnabled == 0 )
    {
        // Initialize Winsock
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            SAFE_CALL( debugfunc, data, NO_PREFIX, "WSAStartup failed: %d\n", iResult);
            return 1;
        }
        socketsEnabled = 1;
    }
#endif
    *otherSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*otherSock == INVALID_SOCKET)
    {
        SAFE_CALL( debugfunc, data, NO_PREFIX, "socket creation failed with error = %d\n", WSAGetLastError() );
        return(1);
    }
    else {
#ifndef _WIN32
        iResult = setsockopt(*otherSock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
        if (iResult) {
          SAFE_CALL( debugfunc, data, NO_PREFIX, "setsockopt failed with error = %d\n", WSAGetLastError() );
          return(1);
        }
#endif
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
#ifndef _WIN32
        iResult = setsockopt(*tpmSock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
        if (iResult) {
          SAFE_CALL( debugfunc, data, NO_PREFIX, "setsockopt failed with error = %d\n", WSAGetLastError() );
          closesocket(*otherSock);
          WSACleanup();
          return(1);
        }
#endif
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
