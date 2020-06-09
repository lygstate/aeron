#include <stdint.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
char buffer[1024];
WSABUF buf;

void aeron_net_init()
{
    static int started = -1;
    if (started == -1)
    {
        const WORD wVersionRequested = MAKEWORD(2, 2);
        WSADATA buffer;
        if (WSAStartup(wVersionRequested, &buffer))
        {
            return;
        }

        started = 0;
    }
}

int main()
{
    aeron_net_init();
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // create UDP socket somehow

    DWORD if_addr_ipv4 = 0;
    inet_pton(AF_INET, "192.168.199.5", &if_addr_ipv4);

    struct sockaddr_in bindInterfaceAddr;
    memset(&bindInterfaceAddr, 0, sizeof(bindInterfaceAddr));
    bindInterfaceAddr.sin_family = AF_INET;
    bindInterfaceAddr.sin_addr.s_addr = if_addr_ipv4;
    bindInterfaceAddr.sin_port = 0; // Allow the kernel to choose a random port number by passing in 0 for the port.
    bind(sock, (struct sockaddr *)&bindInterfaceAddr, sizeof(bindInterfaceAddr));

    DWORD ttl = 32;
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&ttl, sizeof(ttl));
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&if_addr_ipv4, sizeof(if_addr_ipv4));
    u_long iMode = 1;
    int iResult = ioctlsocket(sock, FIONBIO, &iMode);

    struct sockaddr_in RecvAddr;

    RecvAddr.sin_family = AF_INET;

    inet_pton(AF_INET, "239.255.0.1", &(RecvAddr.sin_addr.s_addr));
    if (RecvAddr.sin_addr.s_addr == INADDR_NONE)
    {
        printf("The target ip address entered must be a legal IPv4 address\n");
        WSACleanup();
        return 1;
    }
    RecvAddr.sin_port = htons((u_short)atoi("29375"));
    if (RecvAddr.sin_port == 0)
    {
        printf("The targetport must be a legal UDP port number\n");
        WSACleanup();
        return 1;
    }

    long totalSize = 0;
    long long fullSize = 0;
    for (;;)
    {
        buf.buf = buffer;
        buf.len = sizeof(buffer);
        memset(buffer, 0, sizeof(buffer));

        DWORD size;

        const int result = WSASendTo(
            sock,
            &buf,
            1,
            &size,
            MSG_DONTROUTE,
            (SOCKADDR *)&RecvAddr,
            sizeof(RecvAddr),
            NULL,
            NULL);
        if (result >= 0)
        {
            totalSize += size;
        }
        if (totalSize > 1024 * 1024)
        {
            fullSize += totalSize;
            printf("%d size:%d allSize:%lld\n", result, totalSize, fullSize / 1024 / 1024);
            totalSize = 0;
        }
    }
    return 0;
}