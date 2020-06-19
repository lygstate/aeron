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

#define sockaddr_storage_use_system

#include "aeron_socket.h"

#if defined(AERON_COMPILER_GCC)

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

#elif defined(AERON_COMPILER_MSVC)

#if _WIN32_WINNT < 0x0600
#error Unsupported windows version
#endif

void aeron_net_init()
{
    const WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA buffer;
    if (WSAStartup(wVersionRequested, &buffer))
    {
        return;
    }
}

void aeron_net_term()
{
    WSACleanup();
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

    if (dwRet != ERROR_SUCCESS)
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
    if (current == NULL)
    {
        return;
    }

    while (1)
    {
        struct ifaddrs *next = current->ifa_next;
        free(current);
        current = next;

        if (current == NULL)
        {
            break;
        }
    }
}

#include <Mswsock.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdio.h>

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

aeron_socket_t aeron_socket(int domain, int type, int protocol)
{
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

/* aeron_getsockopt and aeron_setsockopt ensure a consistent signature between platforms
 * (MSVC uses char* instead of void* for optval, which causes warnings)
 */
int aeron_getsockopt(aeron_socket_t fd, int level, int optname, void *optval, socklen_t *optlen)
{
    return getsockopt(fd, level, optname, optval, optlen);
}

int aeron_setsockopt(aeron_socket_t fd, int level, int optname, const void *optval, socklen_t optlen)
{
    return setsockopt(fd, level, optname, optval, optlen);
}

#if defined(__linux__)
#define _BSD_SOURCE
#define _GNU_SOURCE
#endif
#define sockaddr_storage_use_system
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "util/aeron_netutil.h"
#include "util/aeron_error.h"
#include "util/aeron_parse_util.h"
#include "aeron_socket.h"
#include "aeron_windows.h"

#if defined(AERON_COMPILER_GCC)

#elif defined(AERON_COMPILER_MSVC)
#include <intrin.h>
#define __builtin_bswap32 _byteswap_ulong
#define __builtin_bswap64 _byteswap_uint64
#define __builtin_popcount __popcnt

#if defined(AERON_CPU_X64)
#define __builtin_popcountll __popcnt64
#else
__inline DWORD64 __builtin_popcountll (
    _In_ DWORD64 operand
    )
{
    return __popcnt((DWORD)(operand >> 32)) + __popcnt((DWORD)(operand & UINT32_MAX));
}

#endif
#else
#error Unsupported platform!
#endif

static aeron_uri_hostname_resolver_func_t aeron_uri_hostname_resolver_func = NULL;

static void *aeron_uri_hostname_resolver_clientd = NULL;

int aeron_ip_addr_resolver(const char *host, struct sockaddr_storage *sockaddr, int family_hint, int protocol)
{
    struct addrinfo hints;
    struct addrinfo *info = NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = family_hint;
    hints.ai_socktype = (IPPROTO_UDP == protocol) ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = protocol;

    int error, result = -1;
    if ((error = getaddrinfo(host, NULL, &hints, &info)) != 0)
    {
        if (NULL == aeron_uri_hostname_resolver_func)
        {
            aeron_set_err(EINVAL, "Unable to resolve host=(%s): (%d) %s", host, error, gai_strerror(error));
            return -1;
        }
        else if (aeron_uri_hostname_resolver_func(aeron_uri_hostname_resolver_clientd, host, &hints, &info) != 0)
        {
            aeron_set_err(EINVAL, "Unable to resolve host=(%s): %s", host, aeron_errmsg());
            return -1;
        }
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

bool aeron_try_parse_ipv4(const char *host, struct sockaddr_storage *sockaddr)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)sockaddr;

    if (inet_pton(AF_INET, host, &addr->sin_addr))
    {
        sockaddr->ss_family = AF_INET;
        return true;
    }

    return false;
}

int aeron_ipv4_addr_resolver(const char *host, int protocol, struct sockaddr_storage *sockaddr)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)sockaddr;

    if (inet_pton(AF_INET, host, &addr->sin_addr))
    {
        sockaddr->ss_family = AF_INET;
        return 0;
    }

    return aeron_ip_addr_resolver(host, sockaddr, AF_INET, protocol);
}

bool aeron_try_parse_ipv6(const char *host, struct sockaddr_storage *sockaddr)
{
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sockaddr;

    if (inet_pton(AF_INET6, host, &addr->sin6_addr))
    {
        sockaddr->ss_family = AF_INET6;
        return true;
    }

    return false;
}

int aeron_ipv6_addr_resolver(const char *host, int protocol, struct sockaddr_storage *sockaddr)
{
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sockaddr;

    if (inet_pton(AF_INET6, host, &addr->sin6_addr))
    {
        sockaddr->ss_family = AF_INET6;
        return 0;
    }

    return aeron_ip_addr_resolver(host, sockaddr, AF_INET6, protocol);
}

int aeron_udp_port_resolver(const char *port_str, bool optional)
{
    if (':' == *port_str)
    {
        port_str++;
    }

    if ('\0' == *port_str)
    {
        if (optional)
        {
            return 0;
        }
    }

    errno = 0;
    char *end_ptr = NULL;
    unsigned long value = strtoul(port_str, &end_ptr, 0);

    if ((0 == value && 0 != errno) || end_ptr == port_str)
    {
        aeron_set_err(EINVAL, "port invalid: %s", port_str);
        return -1;
    }
    else if (value >= UINT16_MAX)
    {
        aeron_set_err(EINVAL, "port out of range: %s", port_str);
        return -1;
    }

    return (int)value;
}

int aeron_prefixlen_resolver(const char *prefixlen, unsigned long max)
{
    if ('\0' == *prefixlen)
    {
        return (int)max;
    }

    if ('/' == *prefixlen)
    {
        prefixlen++;
    }

    if (strcmp("0", prefixlen) == 0)
    {
        return 0;
    }

    errno = 0;
    char *end_ptr = NULL;
    unsigned long value = strtoul(prefixlen, &end_ptr, 0);

    if ((0 == value && 0 != errno) || end_ptr == prefixlen)
    {
        aeron_set_err(EINVAL, "prefixlen invalid: %s", prefixlen);
        return -1;
    }
    else if (value > max)
    {
        aeron_set_err(EINVAL, "prefixlen out of range: %s", prefixlen);
        return -1;
    }

    return (int)value;
}

int aeron_host_port_prefixlen_resolver(
    const char *host_str,
    const char *port_str,
    const char *prefixlen_str,
    struct sockaddr_storage *sockaddr,
    size_t *prefixlen,
    int family_hint)
{
    int host_result = -1, prefixlen_result = -1, port_result = aeron_udp_port_resolver(port_str, true);

    if (AF_INET == family_hint)
    {
        host_result = aeron_ipv4_addr_resolver(host_str, IPPROTO_UDP, sockaddr);
        ((struct sockaddr_in *)sockaddr)->sin_port = htons((uint16_t)port_result);
    }
    else if (AF_INET6 == family_hint)
    {
        host_result = aeron_ipv6_addr_resolver(host_str, IPPROTO_UDP, sockaddr);
        ((struct sockaddr_in6 *)sockaddr)->sin6_port = htons((uint16_t)port_result);
    }

    if (host_result >= 0 && port_result >= 0)
    {
        prefixlen_result = aeron_prefixlen_resolver(prefixlen_str, sockaddr->ss_family == AF_INET6 ? 128 : 32);
        if (prefixlen_result >= 0)
        {
            *prefixlen = (size_t)prefixlen_result;
        }
    }

    return prefixlen_result >= 0 ? 0 : prefixlen_result;
}

int aeron_interface_parse_and_resolve(const char *interface_str, struct sockaddr_storage *sockaddr, size_t *prefixlen)
{
    aeron_parsed_interface_t parsed_interface;

    if (-1 == aeron_interface_split(interface_str, &parsed_interface))
    {
        return -1;
    }

    if (6 == parsed_interface.ip_version_hint)
    {
        return aeron_host_port_prefixlen_resolver(
            parsed_interface.host, parsed_interface.port, parsed_interface.prefix, sockaddr, prefixlen, AF_INET6);
    }

    return aeron_host_port_prefixlen_resolver(
        parsed_interface.host, parsed_interface.port, parsed_interface.prefix, sockaddr, prefixlen, AF_INET);
}

static aeron_getifaddrs_func_t aeron_getifaddrs_func = getifaddrs;

static aeron_freeifaddrs_func_t aeron_freeifaddrs_func = freeifaddrs;

void aeron_set_getifaddrs(aeron_getifaddrs_func_t get_func, aeron_freeifaddrs_func_t free_func)
{
    aeron_getifaddrs_func = get_func;
    aeron_freeifaddrs_func = free_func;
}

int aeron_lookup_interfaces(aeron_ifaddr_func_t func, void *clientd)
{
    struct ifaddrs *ifaddrs = NULL;
    int result = -1;

    if (aeron_getifaddrs_func(&ifaddrs) >= 0)
    {
        result = aeron_lookup_interfaces_from_ifaddrs(func, clientd, ifaddrs);
        aeron_freeifaddrs_func(ifaddrs);
    }

    return result;
}

int aeron_lookup_interfaces_from_ifaddrs(aeron_ifaddr_func_t func, void *clientd, struct ifaddrs *ifaddrs)
{
    int result = 0;
    for (struct ifaddrs *ifa = ifaddrs; ifa != NULL; ifa  = ifa->ifa_next)
    {
        if (NULL == ifa->ifa_addr)
        {
            continue;
        }

        result += func(
            clientd,
            ifa->ifa_name,
            ifa->ifa_addr,
            ifa->ifa_netmask,
            ifa->ifa_flags);
    }

    return result;
}

uint32_t aeron_ipv4_netmask_from_prefixlen(size_t prefixlen)
{
    uint32_t value;

    if (0 == prefixlen)
    {
        value = ~(-1);
    }
    else
    {
        value = ~(((uint32_t)1 << (32 - prefixlen)) - 1);
    }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    value = __builtin_bswap32(value);
#endif

    return value;
}

bool aeron_ipv4_does_prefix_match(struct in_addr *in_addr1, struct in_addr *in_addr2, size_t prefixlen)
{
    uint32_t addr1;
    uint32_t addr2;
    uint32_t netmask = aeron_ipv4_netmask_from_prefixlen(prefixlen);

    memcpy(&addr1, in_addr1, sizeof(addr1));
    memcpy(&addr2, in_addr2, sizeof(addr2));

    return (addr1 & netmask) == (addr2 & netmask);
}

size_t aeron_ipv4_netmask_to_prefixlen(struct in_addr *netmask)
{
    return __builtin_popcount(netmask->s_addr);
}

void aeron_set_ipv4_wildcard_host_and_port(struct sockaddr_storage *sockaddr)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)sockaddr;

    sockaddr->ss_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;
    addr->sin_port = htons(0);
}

#if defined(AERON_COMPILER_GCC)
union _aeron_128b_as_64b
{
    __uint128_t value;
    uint64_t q[2];
};

__uint128_t aeron_ipv6_netmask_from_prefixlen(size_t prefixlen)
{
    union _aeron_128b_as_64b netmask;

    if (0 == prefixlen)
    {
        netmask.value = ~(-1);
    }
    else
    {
        netmask.value = ~(((__uint128_t)1 << (128 - prefixlen)) - (__uint128_t)1);
    }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint64_t q1 = netmask.q[1];
    netmask.q[1] = __builtin_bswap64(netmask.q[0]);
    netmask.q[0] = __builtin_bswap64(q1);
#endif

    return netmask.value;
}

bool aeron_ipv6_does_prefix_match(struct in6_addr *in6_addr1, struct in6_addr *in6_addr2, size_t prefixlen)
{
    __uint128_t addr1;
    __uint128_t addr2;
    __uint128_t netmask = aeron_ipv6_netmask_from_prefixlen(prefixlen);

    memcpy(&addr1, in6_addr1, sizeof(addr1));
    memcpy(&addr2, in6_addr2, sizeof(addr2));

    return (addr1 & netmask) == (addr2 & netmask);
}
#else
union _aeron_128b_as_64b
{
    uint64_t q[2];
};
#endif

size_t aeron_ipv6_netmask_to_prefixlen(struct in6_addr *netmask)
{
    union _aeron_128b_as_64b value;

    memcpy(&value, netmask, sizeof(value));

    return __builtin_popcountll(value.q[0]) + __builtin_popcountll(value.q[1]);
}

bool aeron_ip_does_prefix_match(struct sockaddr *addr1, struct sockaddr *addr2, size_t prefixlen)
{
    bool result = false;

    if (addr1->sa_family == addr2->sa_family)
    {
        if (AF_INET6 == addr1->sa_family)
        {
            result = aeron_ipv6_does_prefix_match(
                &((struct sockaddr_in6 *)addr1)->sin6_addr,
                &((struct sockaddr_in6 *)addr2)->sin6_addr,
                prefixlen);
        }
        else if (AF_INET == addr1->sa_family)
        {
            result = aeron_ipv4_does_prefix_match(
                &((struct sockaddr_in *)addr1)->sin_addr,
                &((struct sockaddr_in *)addr2)->sin_addr,
                prefixlen);
        }
    }

    return result;
}

size_t aeron_ip_netmask_to_prefixlen(struct sockaddr *netmask)
{
    return AF_INET6 == netmask->sa_family ?
        aeron_ipv6_netmask_to_prefixlen(&((struct sockaddr_in6 *)netmask)->sin6_addr) :
        aeron_ipv4_netmask_to_prefixlen(&((struct sockaddr_in *)netmask)->sin_addr);
}

struct lookup_state
{
    struct sockaddr_storage lookup_addr;
    struct sockaddr_storage *if_addr;
    unsigned int *if_index;
    unsigned int if_flags;
    size_t prefixlen;
    size_t if_prefixlen;
    bool found;
};

int aeron_ip_lookup_func(
    void *clientd, const char *name, struct sockaddr *addr, struct sockaddr *netmask, unsigned int flags)
{
    if (flags & IFF_UP)
    {
        struct lookup_state *state = (struct lookup_state *)clientd;

        if (aeron_ip_does_prefix_match((struct sockaddr *)&state->lookup_addr, addr, state->prefixlen))
        {
            size_t addr_len = AF_INET6 == addr->sa_family ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

            if ((flags & IFF_LOOPBACK) && !state->found)
            {
                memcpy(state->if_addr, addr, addr_len);
                *state->if_index = if_nametoindex(name);
                state->found = true;
                return 1;
            }
            else if (flags & IFF_MULTICAST)
            {
                size_t current_if_prefixlen = aeron_ip_netmask_to_prefixlen(netmask);

                if (current_if_prefixlen > state->if_prefixlen)
                {
                    memcpy(state->if_addr, addr, addr_len);
                    *state->if_index = if_nametoindex(name);
                    state->if_prefixlen = current_if_prefixlen;
                }

                state->found = true;
                return 1;
            }
        }
    }

    return 0;
}

void aeron_ip_copy_port(struct sockaddr_storage *dest_addr, struct sockaddr_storage *src_addr)
{
    if (AF_INET6 == src_addr->ss_family)
    {
        struct sockaddr_in6 *dest = (struct sockaddr_in6 *)dest_addr;
        struct sockaddr_in6 *src = (struct sockaddr_in6 *)src_addr;

        dest->sin6_port = src->sin6_port;
    }
    else if (AF_INET == src_addr->ss_family)
    {
        struct sockaddr_in *dest = (struct sockaddr_in *)dest_addr;
        struct sockaddr_in *src = (struct sockaddr_in *)src_addr;

        dest->sin_port = src->sin_port;
    }
}

int aeron_find_interface(const char *interface_str, struct sockaddr_storage *if_addr, unsigned int *if_index)
{
    struct lookup_state state;

    if (aeron_interface_parse_and_resolve(interface_str, &state.lookup_addr, &state.prefixlen) < 0)
    {
        return -1;
    }

    state.if_addr = if_addr;
    state.if_index = if_index;
    state.if_prefixlen = 0;
    state.if_flags = 0;
    state.found = false;

    int result = aeron_lookup_interfaces(aeron_ip_lookup_func, &state);

    if (0 == result)
    {
        aeron_set_err(EINVAL, "could not find matching interface=(%s)", interface_str);
        return -1;
    }

    aeron_ip_copy_port(if_addr, &state.lookup_addr);

    return 0;
}

int aeron_find_unicast_interface(
    int family, const char *interface_str, struct sockaddr_storage *interface_addr, unsigned int *interface_index)
{
    *interface_index = 0;

    if (NULL != interface_str)
    {
        struct sockaddr_storage tmp_addr;
        size_t prefixlen = 0;

        if (aeron_interface_parse_and_resolve(interface_str, &tmp_addr, &prefixlen) >= 0 &&
            aeron_is_wildcard_addr(&tmp_addr))
        {
            memcpy(interface_addr, &tmp_addr, sizeof(tmp_addr));
            return 0;
        }

        return aeron_find_interface(interface_str, interface_addr, interface_index);
    }
    else if (AF_INET6 == family)
    {
        interface_addr->ss_family = AF_INET6;
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)interface_addr;
        addr->sin6_addr = in6addr_any;
        addr->sin6_port = htons(0);
    }
    else
    {
        interface_addr->ss_family = AF_INET;
        struct sockaddr_in *addr = (struct sockaddr_in *)interface_addr;
        addr->sin_addr.s_addr = INADDR_ANY;
        addr->sin_port = htons(0);
    }

    return 0;
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

bool aeron_is_wildcard_addr(struct sockaddr_storage *addr)
{
    bool result = false;

    if (AF_INET6 == addr->ss_family)
    {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)addr;

        return memcmp(&a->sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0 ? true : false;
    }
    else if (AF_INET == addr->ss_family)
    {
        struct sockaddr_in *a = (struct sockaddr_in *)addr;

        result = a->sin_addr.s_addr == INADDR_ANY;
    }

    return result;
}

bool aeron_is_wildcard_port(struct sockaddr_storage *addr)
{
    bool result = false;

    if (AF_INET6 == addr->ss_family)
    {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)addr;

        return 0 == a->sin6_port;
    }
    else if (AF_INET == addr->ss_family)
    {
        struct sockaddr_in *a = (struct sockaddr_in *)addr;

        result = 0 == a->sin_port;
    }

    return result;
}

int aeron_format_source_identity(char *buffer, size_t length, struct sockaddr_storage *addr)
{
    char addr_str[INET6_ADDRSTRLEN] = "";
    unsigned short port = 0;

    if (length < AERON_NETUTIL_FORMATTED_MAX_LENGTH)
    {
        return -ENOSPC;
    }

    int total = 0;
    if (AF_INET6 == addr->ss_family)
    {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;

        inet_ntop(addr->ss_family, &in6->sin6_addr, addr_str, sizeof(addr_str));
        port = ntohs(in6->sin6_port);
        total = snprintf(buffer, length, "[%s]:%d", addr_str, port);
    }
    else if (AF_INET == addr->ss_family)
    {
        struct sockaddr_in *in4 = (struct sockaddr_in *)addr;

        inet_ntop(addr->ss_family, &in4->sin_addr, addr_str, sizeof(addr_str));
        port = ntohs(in4->sin_port);
        total = snprintf(buffer, length, "%s:%d", addr_str, port);
    }

    if (total < 0)
    {
        return 0;
    }

    return total;
}


int aeron_ipv4_multicast_control_address(struct sockaddr_in *data_addr, struct sockaddr_in *control_addr)
{
    uint8_t bytes[sizeof(struct in_addr)];
    size_t addr_len = sizeof(struct in_addr);
    size_t last_byte_index = addr_len - 1;

    memcpy(bytes, &(data_addr->sin_addr), addr_len);

    if ((bytes[last_byte_index] & 0x1) == 0)
    {
        aeron_set_err(EINVAL, "%s", "Multicast data address must be odd");
        return -1;
    }

    bytes[last_byte_index]++;
    control_addr->sin_family = data_addr->sin_family;
    memcpy(&(control_addr->sin_addr), bytes, addr_len);
    control_addr->sin_port = data_addr->sin_port;

    return 0;
}

int aeron_ipv6_multicast_control_address(struct sockaddr_in6 *data_addr, struct sockaddr_in6 *control_addr)
{
    uint8_t bytes[sizeof(struct in6_addr)];
    size_t addr_len = sizeof(struct in6_addr);
    size_t last_byte_index = addr_len - 1;

    memcpy(bytes, &(data_addr->sin6_addr), addr_len);

    if ((bytes[last_byte_index] & 0x1) == 0)
    {
        aeron_set_err(EINVAL, "%s", "Multicast data address must be odd");
        return -1;
    }

    bytes[last_byte_index]++;
    control_addr->sin6_family = data_addr->sin6_family;
    memcpy(&(control_addr->sin6_addr), bytes, addr_len);
    control_addr->sin6_port = data_addr->sin6_port;

    return 0;
}

int aeron_multicast_control_address(struct sockaddr_storage *data_addr, struct sockaddr_storage *control_addr)
{
    if (AF_INET6 == data_addr->ss_family)
    {
        return aeron_ipv6_multicast_control_address(
            (struct sockaddr_in6 *)data_addr, (struct sockaddr_in6 *)control_addr);
    }
    else if (AF_INET == data_addr->ss_family)
    {
        return aeron_ipv4_multicast_control_address(
            (struct sockaddr_in *)data_addr, (struct sockaddr_in *)control_addr);
    }

    aeron_set_err(EINVAL, "unknown address family: %d", data_addr->ss_family);
    return -1;
}

int aeron_find_multicast_interface(
    int family, const char *interface_str, struct sockaddr_storage *interface_addr, unsigned int *interface_index)
{
    char *wildcard_str = AF_INET6 == family ? "[0::]/0" : "0.0.0.0/0";

    return aeron_find_interface(NULL == interface_str ? wildcard_str : interface_str, interface_addr, interface_index);
}
