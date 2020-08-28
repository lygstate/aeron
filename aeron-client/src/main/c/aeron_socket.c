/*
 * Copyright 2014-2020 Real Logic Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#if defined(__linux__)
#define _BSD_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <errno.h>
#include <time.h>

#include "util/aeron_platform.h"

#if defined(AERON_OS_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <wS2tcpip.h>
#include <iphlpapi.h>
#include <mswsock.h>
#endif

#include "util/aeron_error.h"
#include "aeron_socket.h"

#if defined(AERON_OS_POSIX)

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

void aeron_net_init()
{
}

int set_socket_non_blocking(aeron_socket_t fd)
{
    int flags;
    if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
    {
        return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
    {
        return -1;
    }

    return 0;
}

aeron_socket_t aeron_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

void aeron_close_socket(aeron_socket_t socket)
{
    close(socket);
}

#elif defined(AERON_OS_WIN32)

#if _WIN32_WINNT < 0x0600
#error Unsupported windows version
#endif

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

int set_socket_non_blocking(aeron_socket_t fd)
{
    u_long iMode = 1;
    int iResult = ioctlsocket(fd, FIONBIO, &iMode);
    if (iResult != NO_ERROR)
    {
        return -1;
    }

    return 0;
}

int getifaddrs(struct ifaddrs **ifap)
{
    DWORD MAX_TRIES = 2;
    DWORD dwSize = 10 * sizeof(IP_ADAPTER_ADDRESSES), dwRet;
    IP_ADAPTER_ADDRESSES *pAdapterAddresses = NULL;

    /* loop to handle interfaces coming online causing a buffer overflow
     * between first call to list buffer length and second call to enumerate.
     */
    for (unsigned i = MAX_TRIES; i; i--)
    {
        pAdapterAddresses = (IP_ADAPTER_ADDRESSES*)malloc(dwSize);
        dwRet = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX |
            GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_DNS_SERVER |
            GAA_FLAG_SKIP_FRIENDLY_NAME |
            GAA_FLAG_SKIP_MULTICAST,
            NULL,
            pAdapterAddresses,
            &dwSize);

        if (ERROR_BUFFER_OVERFLOW == dwRet)
        {
            free(pAdapterAddresses);
            pAdapterAddresses = NULL;
        }
        else
        {
            break;
        }
    }

    if (ERROR_SUCCESS != dwRet)
    {
        if (pAdapterAddresses)
        {
            free(pAdapterAddresses);
        }

        return -1;
    }

    struct ifaddrs* ifa = malloc(sizeof(struct ifaddrs));
    struct ifaddrs* ift = NULL;

    /* now populate list */
    for (IP_ADAPTER_ADDRESSES* adapter = pAdapterAddresses; adapter; adapter = adapter->Next)
    {
        int unicastIndex = 0;
        for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
            unicast;
            unicast = unicast->Next, ++unicastIndex)
        {
            /* ensure IP adapter */
            if (AF_INET != unicast->Address.lpSockaddr->sa_family &&
                AF_INET6 != unicast->Address.lpSockaddr->sa_family)
            {
                continue;
            }

            /* Next */
            if (ift == NULL)
            {
                ift = ifa;
            }
            else
            {
                ift->ifa_next = malloc(sizeof(struct ifaddrs));
                ift = ift->ifa_next;
            }
            memset(ift, 0, sizeof(struct ifaddrs));

            /* address */
            ift->ifa_addr = malloc(unicast->Address.iSockaddrLength);
            memcpy(ift->ifa_addr, unicast->Address.lpSockaddr, unicast->Address.iSockaddrLength);

            /* name */
            ift->ifa_name = malloc(IF_NAMESIZE);
            strncpy_s(ift->ifa_name, IF_NAMESIZE, adapter->AdapterName, _TRUNCATE);

            /* flags */
            ift->ifa_flags = 0;
            if (IfOperStatusUp == adapter->OperStatus)
            {
                ift->ifa_flags |= IFF_UP;
            }

            if (IF_TYPE_SOFTWARE_LOOPBACK == adapter->IfType)
            {
                ift->ifa_flags |= IFF_LOOPBACK;
            }

            if (!(adapter->Flags & IP_ADAPTER_NO_MULTICAST))
            {
                ift->ifa_flags |= IFF_MULTICAST;
            }

            /* netmask */
            ULONG prefixLength = unicast->OnLinkPrefixLength;

            /* map prefix to netmask */
            ift->ifa_netmask = malloc(sizeof(struct sockaddr));
            ift->ifa_netmask->sa_family = unicast->Address.lpSockaddr->sa_family;

            switch (unicast->Address.lpSockaddr->sa_family)
            {
                case AF_INET:
                    if (0 == prefixLength || prefixLength > 32)
                    {
                        prefixLength = 32;
                    }

                    ULONG Mask;
                    ConvertLengthToIpv4Mask(prefixLength, &Mask);
                    ((struct sockaddr_in*)ift->ifa_netmask)->sin_addr.s_addr = htonl(Mask);
                    break;

                case AF_INET6:
                    if (0 == prefixLength || prefixLength > 128)
                    {
                        prefixLength = 128;
                    }

                    for (LONG i = prefixLength, j = 0; i > 0; i -= 8, ++j)
                    {
                        ((struct sockaddr_in6*)ift->ifa_netmask)->sin6_addr.s6_addr[j] = i >= 8 ?
                            0xff : (ULONG)((0xffU << (8 - i)) & 0xffU);
                    }
                    break;

                default:
                    break;
            }
        }
    }

    if (pAdapterAddresses)
    {
        free(pAdapterAddresses);
    }

    *ifap = ifa;

    return TRUE;
}

void freeifaddrs(struct ifaddrs *current)
{
    if (NULL != current)
    {
        while (1)
        {
            struct ifaddrs *next = current->ifa_next;
            free(current);
            current = next;

            if (NULL == current)
            {
                break;
            }
        }
    }
}

ssize_t recvmsg(aeron_socket_t fd, struct msghdr *msghdr, int flags)
{
    DWORD size = 0;
    const int result = WSARecvFrom(
        fd,
        (LPWSABUF)msghdr->msg_iov,
        msghdr->msg_iovlen,
        &size,
        &msghdr->msg_flags,
        msghdr->msg_name,
        &msghdr->msg_namelen,
        NULL,
        NULL);

    if (result == SOCKET_ERROR)
    {
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK)
        {
            return 0;
        }

        return -1;
    }

    return size;
}

ssize_t sendmsg(aeron_socket_t fd, struct msghdr *msghdr, int flags)
{
    DWORD size = 0;
    const int result = WSASendTo(
        fd,
        (LPWSABUF)msghdr->msg_iov,
        msghdr->msg_iovlen,
        &size,
        msghdr->msg_flags,
        (const struct sockaddr*)msghdr->msg_name,
        msghdr->msg_namelen,
        NULL,
        NULL);

    if (result == SOCKET_ERROR)
    {
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK)
        {
            return 0;
        }

        return -1;
    }

    return size;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return WSAPoll(fds, nfds, timeout);
}

const char *aeron_inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
    return inet_ntop(af, src, dst, size);
}

int aeron_inet_pton(int af, const char *src, void *dst)
{
    return inet_pton(af, src, dst);
}

uint32_t aeron_htonl(uint32_t hostlong)
{
    return htonl(hostlong);
}

uint16_t aeron_htons(uint16_t hostshort)
{
    return htons(hostshort);
}

uint32_t aeron_ntohl(uint32_t netlong)
{
    return ntohl(netlong);
}

uint16_t aeron_ntohs(uint16_t netshort)
{
    return ntohs(netshort);
}

aeron_socket_t aeron_socket(int domain, int type, int protocol)
{
    aeron_net_init();
    const SOCKET handle = socket(domain, type, protocol);
    return handle != INVALID_SOCKET ? handle : -1;
}

void aeron_close_socket(aeron_socket_t socket)
{
    closesocket(socket);
}

#else
#error Unsupported platform!
#endif

bool aeron_in6_is_addr_linklocal(const struct in6_addr *a)
{
    return IN6_IS_ADDR_LINKLOCAL(a);
}

int aeron_socket_addr_to_string(const struct sockaddr_storage *addr, char* buf, socklen_t buf_size)
{
    const void *in_addr = addr->ss_family == AF_INET ?
        (const void *)&((struct sockaddr_in *)addr)->sin_addr :
        (const void *)&((struct sockaddr_in6 *)addr)->sin6_addr;

    if (inet_ntop(
        addr->ss_family,
                in_addr,
                buf,
                buf_size) == NULL)
    {
        aeron_set_err_from_last_err_code("aeron_socket_addr_to_string failed");
        return -1;
    }
    return 0;
}

uint16_t aeron_socket_addr_port(const struct sockaddr_storage *addr)
{
    uint16_t net_port = addr->ss_family == AF_INET ?
        ((struct sockaddr_in *)addr)->sin_port :
        ((struct sockaddr_in6 *)addr)->sin6_port;
    return ntohs(net_port);
}

unsigned int aeron_if_nametoindex(const char *name)
{
    return if_nametoindex(name);
}

struct in6_addr aeron_in6addr_any()
{
    return in6addr_any;
}

int aeron_bind(aeron_socket_t sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return bind(sockfd, addr, addrlen);
}

int aeron_getsockname(aeron_socket_t sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return getsockname(sockfd, addr, addrlen);
}

int aeron_gethostname(char *name, size_t len)
{
    return gethostname(name, (int)len);
}

int aeron_ip_addr_resolver(const char *host, const char *service, struct sockaddr_storage *sockaddr, int family_hint, int protocol)
{
    aeron_net_init();

    struct addrinfo hints;
    struct addrinfo *info = NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = family_hint;
    hints.ai_socktype = (IPPROTO_UDP == protocol) ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = protocol;

    int error, result = -1;
    if ((error = getaddrinfo(host, service, &hints, &info)) != 0)
    {
        aeron_set_err(EINVAL, "Unable to resolve host=(%s): (%d) %s", host, error, gai_strerror(error));
        return -1;
    }

    if (info->ai_family == AF_INET)
    {
        memcpy(sockaddr, info->ai_addr, sizeof(struct sockaddr_in));
        sockaddr->ss_family = AF_INET;
        result = 0;
    }
    else if (info->ai_family == AF_INET6)
    {
        memcpy(sockaddr, info->ai_addr, sizeof(struct sockaddr_in6));
        sockaddr->ss_family = AF_INET6;
        result = 0;
    }
    else
    {
        aeron_set_err(EINVAL, "Only IPv4 and IPv6 hosts are supported: family=%d", info->ai_family);
    }

    freeaddrinfo(info);

    return result;
}

bool aeron_is_addr_multicast(struct sockaddr_storage *addr)
{
    bool result = false;

    if (AF_INET6 == addr->ss_family)
    {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)addr;

        result = IN6_IS_ADDR_MULTICAST(&a->sin6_addr);
    }
    else if (AF_INET == addr->ss_family)
    {
        struct sockaddr_in *a = (struct sockaddr_in *)addr;

        result = IN_MULTICAST(ntohl(a->sin_addr.s_addr));
    }

    return result;
}

int aeron_udp_recvmmsg(
    aeron_socket_t fd,
    void *context,
    struct aeron_mmsghdr *msgvec,
    size_t count,
    int *bytes_rcved,
    aeron_udp_recv_func_t recv_func)
{
    *bytes_rcved = 0;
#if defined(HAVE_RECVMMSG)
    struct timespec tv = { .tv_nsec = 0, .tv_sec = 0 };

    int result = recvmmsg(fd, (struct mmsghdr *)msgvec, count, 0, &tv);
    if (result < 0)
    {
        int err = errno;

        if (EINTR == err || EAGAIN == err)
        {
            return 0;
        }

        aeron_set_err_from_last_err_code("recvmmsg");
        return -1;
    }
    else if (0 == result)
    {
        return 0;
    }
    else
    {
        for (size_t i = 0, length = (size_t)result; i < length; i++)
        {
            recv_func(
                context,
                msgvec[i].msg_hdr.msg_iov[0].iov_base,
                msgvec[i].msg_len,
                msgvec[i].msg_hdr.msg_name);
            *bytes_rcved += msgvec[i].msg_len;
        }

        return result;
    }
#else
    int work_count = 0;

    for (size_t i = 0, length = count; i < length; i++)
    {
        ssize_t result = recvmsg(fd, &msgvec[i].msg_hdr, 0);

        if (result < 0)
        {
            int err = errno;

            if (EINTR == err || EAGAIN == err)
            {
                break;
            }

            aeron_set_err_from_last_err_code("recvmsg");
            return -1;
        }

        if (0 == result)
        {
            break;
        }

        msgvec[i].msg_len = (unsigned int)result;
        recv_func(
            context,
            msgvec[i].msg_hdr.msg_iov[0].iov_base,
            msgvec[i].msg_len,
            msgvec[i].msg_hdr.msg_name);
        *bytes_rcved += msgvec[i].msg_len;
        work_count++;
    }

    return work_count;
#endif
}

int aeron_udp_sendmmsg(
    aeron_socket_t fd,
    struct aeron_mmsghdr *msgvec,
    size_t count,
    int *bytes_sent)
{
    int result = 0;
#if defined(HAVE_SENDMMSG)
    result = sendmmsg(fd, (struct mmsghdr *)msgvec, count, 0);
    if (result < 0)
    {
        aeron_set_err_from_last_err_code("sendmmsg");
        result = -1;
        return -1;
    }
#else

    for (size_t i = 0; i < count; i++)
    {
        ssize_t sendmsg_result = sendmsg(fd, &msgvec[i].msg_hdr, 0);
        if (sendmsg_result < 0)
        {
            aeron_set_err_from_last_err_code("sendmsg");
            result = -1;
            break;
        }

        msgvec[i].msg_len = (unsigned int)sendmsg_result;

        result++;

        if (sendmsg_result < (ssize_t)msgvec[i].msg_hdr.msg_iov->iov_len)
        {
            break;
        }
    }
#endif
    *bytes_sent = 0;

    for (int i = 0; i < result; i += 1)
    {
        *bytes_sent += msgvec[i].msg_len;
        if (msgvec[i].msg_len == 0)
        {
            break;
        }
        if (msgvec[i].msg_len < msgvec->msg_hdr.msg_iov[i].iov_len)
        {
            result = i + 1;
            break;
        }
    }

    return result;
}

/* aeron_getsockopt and aeron_setsockopt ensure a consistent signature between platforms
 * (MSVC uses char * instead of void * for optval, which causes warnings)
 */
int aeron_getsockopt(aeron_socket_t fd, int level, int optname, void *optval, socklen_t *optlen)
{
    return getsockopt(fd, level, optname, optval, optlen);
}

int aeron_setsockopt(aeron_socket_t fd, int level, int optname, const void *optval, socklen_t optlen)
{
    return setsockopt(fd, level, optname, optval, optlen);
}
