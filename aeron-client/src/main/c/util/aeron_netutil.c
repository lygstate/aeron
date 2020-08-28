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

#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include "util/aeron_netutil.h"
#include "util/aeron_error.h"
#include "util/aeron_parse_util.h"

#if defined(AERON_COMPILER_GCC)

#elif defined(AERON_OS_WIN32)
#include <intrin.h>
#define __builtin_bswap32 _byteswap_ulong
#define __builtin_bswap64 _byteswap_uint64
#define __builtin_popcount __popcnt

#if defined(AERON_CPU_X64)
#define __builtin_popcountll __popcnt64
#else
__inline DWORD64 __builtin_popcountll(DWORD64 operand)
{
    return __popcnt((DWORD)(operand >> 32)) + __popcnt((DWORD)(operand & UINT32_MAX));
}
#endif

#else
#error Unsupported platform!
#endif

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

    return aeron_ip_addr_resolver(host, NULL, sockaddr, AF_INET, protocol);
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

    return aeron_ip_addr_resolver(host, NULL, sockaddr, AF_INET6, protocol);
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
union aeron_128b_as_64b
{
    __uint128_t value;
    uint64_t q[2];
};

__uint128_t aeron_ipv6_netmask_from_prefixlen(size_t prefixlen)
{
    union aeron_128b_as_64b netmask;

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
union aeron_128b_as_64b
{
    uint64_t q[2];
};
#endif

size_t aeron_ipv6_netmask_to_prefixlen(struct in6_addr *netmask)
{
    union aeron_128b_as_64b value;

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
                *state->if_index = aeron_if_nametoindex(name);
                state->found = true;
                return 1;
            }
            else if (flags & IFF_MULTICAST)
            {
                size_t current_if_prefixlen = aeron_ip_netmask_to_prefixlen(netmask);

                if (current_if_prefixlen > state->if_prefixlen)
                {
                    memcpy(state->if_addr, addr, addr_len);
                    *state->if_index = aeron_if_nametoindex(name);
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
        addr->sin6_addr = aeron_in6addr_any();
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

bool aeron_is_wildcard_addr(struct sockaddr_storage *addr)
{
    bool result = false;

    if (AF_INET6 == addr->ss_family)
    {
        struct in6_addr in6addr_any = aeron_in6addr_any();
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

    if (length < AERON_NETUTIL_FORMATTED_MAX_LENGTH)
    {
        return -ENOSPC;
    }

    int total = 0;
    if (AF_INET6 == addr->ss_family)
    {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;

        inet_ntop(addr->ss_family, &in6->sin6_addr, addr_str, sizeof(addr_str));
        unsigned short port = ntohs(in6->sin6_port);
        total = snprintf(buffer, length, "[%s]:%d", addr_str, port);
    }
    else if (AF_INET == addr->ss_family)
    {
        struct sockaddr_in *in4 = (struct sockaddr_in *)addr;

        inet_ntop(addr->ss_family, &in4->sin_addr, addr_str, sizeof(addr_str));
        unsigned short port = ntohs(in4->sin_port);
        total = snprintf(buffer, length, "%s:%d", addr_str, port);
    }

    if (total < 0)
    {
        return 0;
    }

    return total;
}

/*
Win32 socket opts
https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options

Posix:
https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_10_16
*/

static int set_dont_route(aeron_socket_t socket, bool ipv6)
{
    if (ipv6)
    {
        const unsigned uone = 1;
        if (aeron_setsockopt(socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &uone, sizeof(uone)) < 0)
        {
            aeron_set_err_from_last_err_code("set_dont_route(IPV6_UNICAST_HOPS)");
            return -1;
        }
        return 0;
    }
    else
    {
        const int one = 1;
        if (aeron_setsockopt(socket, SOL_SOCKET, SO_DONTROUTE, &one, sizeof(one)) < 0)
        {
            aeron_set_err_from_last_err_code("set_dont_route(SO_DONTROUTE)");
            return -1;
        }
        return 0;
    }
}

static int set_rcvbuf(aeron_socket_t sock, size_t socket_min_rcvbuf_size)
{
    size_t size;
    socklen_t optlen = (socklen_t)sizeof(size);

    if (aeron_getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, &optlen) < 0)
    {
        /* not all stacks support getting/setting RCVBUF */
        if (errno == ENOPROTOOPT)
        {
            aeron_set_err(0, "set_rcvbuf: cannot retrieve socket receive buffer size");
            return 0;
        }
        aeron_set_err_from_last_err_code("set_rcvbuf: get SO_RCVBUF failed");
        return -1;
    }

    if (size < socket_min_rcvbuf_size)
    {
        /* make sure the receive buffersize is at least the minimum required */
        size = socket_min_rcvbuf_size;
        aeron_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

        /* We don't check the return code from setsockopt, because some O/Ss tend
        to silently cap the buffer size.  The only way to make sure is to read
        the option value back and check it is now set correctly. */
        optlen = (socklen_t)sizeof(size);
        if (aeron_getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, &optlen) < 0)
        {
            aeron_set_err_from_last_err_code("set_rcvbuf: get SO_RCVBUF failed");
            return -1;
        }

        if (size < socket_min_rcvbuf_size)
        {
            aeron_set_err(EINVAL, "set_rcvbuf: failed to increase socket receive buffer size to %" PRIu32 " bytes, maximum is %" PRIu32 " bytes\n",
                          (uint32_t)socket_min_rcvbuf_size, (uint32_t)size);
        }
    }

    return 0;
}

static int set_sndbuf(aeron_socket_t sock, size_t socket_min_sndbuf_size)
{
    size_t size;
    socklen_t optlen = (socklen_t)sizeof(size);
    if (aeron_getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, &optlen) < 0)
    {
        /* not all stacks support getting/setting SNDBUF */
        if (errno == ENOPROTOOPT)
        {
            aeron_set_err(0, "set_sndbuf: cannot retrieve socket send buffer size");
            return 0;
        }
        aeron_set_err_from_last_err_code("set_sndbuf: get SO_SNDBUF failed");
        return -1;
    }

    if (size < socket_min_sndbuf_size)
    {
        /* make sure the send buffersize is at least the minimum required */
        size = socket_min_sndbuf_size;
        aeron_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));

        /* We don't check the return code from setsockopt, because some O/Ss tend
       to silently cap the buffer size.  The only way to make sure is to read
       the option value back and check it is now set correctly. */
        optlen = (socklen_t)sizeof(size);
        if (aeron_getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, &optlen) < 0)
        {
            aeron_set_err_from_last_err_code("set_sndbuf: get SO_SNDBUF failed");
            return -1;
        }

        if (size < socket_min_sndbuf_size)
        {
            aeron_set_err(EINVAL, "set_sndbuf: failed to increase socket send buffer size to %" PRIu32 " bytes, maximum is %" PRIu32 " bytes\n",
                          (uint32_t)socket_min_sndbuf_size, (uint32_t)size);
        }
    }

    return 0;
}

static int set_mc_options_transmit_ipv6(aeron_socket_t sock, unsigned interface_no, unsigned ttl, unsigned loop)
{
    /* Function is a never-called no-op if IPv6 is not supported to keep the call-site a bit cleaner  */
    int rc = -1;
    if ((rc = aeron_setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface_no, sizeof(interface_no))) < 0)
    {
        aeron_set_err_from_last_err_code("set_mc_options_transmit_ipv6: set IPV6_MULTICAST_IF failed");
        return -1;
    }
    if ((rc = aeron_setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl))) < 0)
    {
        aeron_set_err_from_last_err_code("set_mc_options_transmit_ipv6: set IPV6_MULTICAST_HOPS failed");
        return -1;
    }
    if ((rc = aeron_setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop))) < 0)
    {
        aeron_set_err_from_last_err_code("set_mc_options_transmit_ipv6: set IPV6_MULTICAST_LOOP failed");
        return -1;
    }
    return 0;
}

static int set_mc_options_transmit_ipv4_if(
    aeron_socket_t sock,
    struct sockaddr_in *interface_addr,
    unsigned interface_no)
{
#if (defined(__linux) || defined(__APPLE__)) && !LWIP_SOCKET
    struct ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    /* looks like imr_multiaddr is not relevant, not sure about imr_address */
    mreqn.imr_multiaddr.s_addr = htonl(INADDR_ANY);
    mreqn.imr_address.s_addr = interface_addr->sin_addr.s_addr;
    mreqn.imr_ifindex = (int)interface_no;
    return aeron_setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn));
#endif
    return aeron_setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &interface_addr->sin_addr, sizeof(struct in_addr));
}

static int set_mc_options_transmit_ipv4(
    aeron_socket_t sock,
    struct sockaddr_storage *interface_addr,
    unsigned interface_no,
    unsigned ttl,
    unsigned loop)
{
    if (set_mc_options_transmit_ipv4_if(sock, (struct sockaddr_in *)interface_addr, interface_no) < 0)
    {
        char buf[AERON_NETUTIL_FORMATTED_MAX_LENGTH];
        aeron_socket_addr_to_string(interface_addr, buf, sizeof(buf));
        aeron_set_err_from_last_err_code("set_mc_options_transmit_ipv4: set IP_MULTICAST_IF with %s failed", buf);
        return -1;
    }
    if (aeron_setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
    {
        aeron_set_err_from_last_err_code("set_mc_options_transmit_ipv4: set IP_MULTICAST_TTL failed");
        return -1;
    }
    if (aeron_setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0)
    {
        aeron_set_err_from_last_err_code("set_mc_options_transmit_ipv4: set IP_MULTICAST_LOOP failed");
        return -1;
    }
    return 0;
}

int aeron_udp_create_conn(
    aeron_socket_t *sock_ptr,
    enum aeron_socket_tran_purpose purpose,
    size_t socket_min_rcvbuf_size,
    size_t socket_min_sndbuf_size,
    struct sockaddr_storage *bind_addr,
    struct sockaddr_storage *interface_addr,
    unsigned interface_no, unsigned ttl, unsigned loop,
    unsigned dont_route,
    int ip_tos)
{
    const int one = 1;

    aeron_socket_t sock = -1;
    bool reuse_addr = false;
    bool bind_to_any = false;
    bool bind_to_any_port = false;
    bool ipv6 = (AF_INET6 == bind_addr->ss_family);
    const char *purpose_str = NULL;
    struct sockaddr_storage final_bind_addr = *bind_addr;
    struct sockaddr_in *in4 = (struct sockaddr_in *)&final_bind_addr;
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&final_bind_addr;
    *sock_ptr = -1;

    switch (purpose)
    {
    case AERON_SOCKET_TRAN_QOS_XMIT:
        reuse_addr = false;
        bind_to_any = false;
        bind_to_any_port = true;
        purpose_str = "transmit";
        break;
    case AERON_SOCKET_TRAN_QOS_UC:
        reuse_addr = false;
        bind_to_any = false;
        bind_to_any_port = false;
        purpose_str = "unicast";
        break;
    case AERON_SOCKET_TRAN_QOS_RECV_MC:
        reuse_addr = true;
        bind_to_any = true;
        bind_to_any_port = false;
        purpose_str = "multicast";
        break;
    default:
        aeron_set_err(EINVAL, "aeron_udp_create_conn: unsupported purpose %d", (int)purpose);
        goto fail;
    }

    switch (bind_addr->ss_family)
    {
    case AF_INET:
    {
        if (bind_to_any)
        {
            in4->sin_addr.s_addr = htonl(INADDR_ANY);
        }
        if (bind_to_any_port)
        {
            in4->sin_port = 0;
        }
        break;
    }
    case AF_INET6:
    {
        if (bind_to_any)
        {
            in6->sin6_addr = aeron_in6addr_any();
        }
        if (bind_to_any_port)
        {
            in6->sin6_port = 0;
        }
        if (aeron_in6_is_addr_linklocal(&(in6->sin6_addr)))
        {
            // A hack that only works if there is only a single interface in use
            in6->sin6_scope_id = interface_no;
        }
        break;
    }
    default:
    {
        aeron_set_err(EINVAL, "aeron_udp_create_conn: unsupported ss_family %" PRId32, bind_addr->ss_family);
        goto fail;
    }
    }

    if ((sock = aeron_socket(bind_addr->ss_family, SOCK_DGRAM, 0)) < 0)
    {
        aeron_set_err_from_last_err_code("aeron_udp_create_conn: failed to create socket");
        goto fail;
    }

    if (reuse_addr && aeron_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
    {
        aeron_set_err_from_last_err_code("aeron_udp_create_conn: failed to enable address reuse");
        if (errno != ENOPROTOOPT)
        {
            /* There must at some point have been an implementation that refused to do SO_REUSEADDR, but I
         don't know which */
            goto fail_w_socket;
        }
    }

#if defined(SO_REUSEPORT)
    if (reuse_addr && aeron_setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
    {
        aeron_set_err_from_last_err_code("aeron_udp_create_conn: failed to enable port reuse");
        goto fail_w_socket;
    }
#endif

    if (set_rcvbuf(sock, socket_min_rcvbuf_size) < 0)
        goto fail_w_socket;

    if (set_sndbuf(sock, socket_min_sndbuf_size) < 0)
        goto fail_w_socket;

    if (dont_route && set_dont_route(sock, ipv6) < 0)
        goto fail_w_socket;

    if (aeron_bind(sock, (struct sockaddr *)&final_bind_addr, AERON_ADDR_LEN(&final_bind_addr)) < 0)
    {
        /* (= EADDRINUSE) is expected if reuse_addr isn't set, should be handled at
       a higher level and therefore needs to return a specific error message */
        char buf[AERON_NETUTIL_FORMATTED_MAX_LENGTH];
        aeron_socket_addr_to_string(&final_bind_addr, buf, sizeof(buf));
        aeron_set_err_from_last_err_code("aeron_udp_create_conn: failed to bind to: %s, purpose_str:%s", buf, purpose_str);
        goto fail_w_socket;
    }

    if (purpose == AERON_SOCKET_TRAN_QOS_XMIT)
    {
        if ((ipv6 ? set_mc_options_transmit_ipv6(sock, interface_no, ttl, loop) : set_mc_options_transmit_ipv4(sock, interface_addr, interface_no, ttl, loop)) < 0)
        {
            goto fail_w_socket;
        }
    }

    if (ip_tos != 0 && !ipv6)
    {
        if (aeron_setsockopt(sock, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos)) < 0)
        {
            aeron_set_err_from_last_err_code("aeron_udp_create_conn: set IP_TOS with %d failed", ip_tos);
            goto fail_w_socket;
        }
    }
    if (set_socket_non_blocking(sock) < 0)
    {
        aeron_set_err_from_last_err_code("set_socket_non_blocking");
        goto fail_w_socket;
    }

    *sock_ptr = sock;
    return 0;
fail_w_socket:
    aeron_close_socket(sock);
fail:
    return -1;
}

int aeron_joinleave_asm_mcgroup(
    aeron_socket_t socket,
    int join,
    const struct sockaddr_storage *multicast_addr,
    const struct sockaddr_storage *interface_addr,
    unsigned int multicast_if_index)
{
    const struct sockaddr_in *in4 = (const struct sockaddr_in *)multicast_addr;
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)multicast_addr;
    if (multicast_addr->ss_family == AF_INET6)
    {
        struct ipv6_mreq ipv6mreq;
        memset(&ipv6mreq, 0, sizeof(ipv6mreq));
        ipv6mreq.ipv6mr_multiaddr = in6->sin6_addr;
        ipv6mreq.ipv6mr_interface = multicast_if_index;
        if (aeron_setsockopt(socket, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &ipv6mreq, sizeof(ipv6mreq)) < 0)
        {
            aeron_set_err_from_last_err_code("%s ipv6 multicast failed", join ? "join" : "leave");
            return -1;
        }
    }
    else
    {
        struct sockaddr_in *interface_addr_in4 = (struct sockaddr_in *)interface_addr;
        struct ip_mreq mreq;
        mreq.imr_multiaddr.s_addr = in4->sin_addr.s_addr;
        mreq.imr_interface.s_addr = interface_addr_in4->sin_addr.s_addr;
        if (aeron_setsockopt(socket, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        {
            aeron_set_err_from_last_err_code("%s ipv4 multicast failed", join ? "join" : "leave");
            return -1;
        }
    }
    return 0;
}

int aeron_joinleave_ssm_mcgroup(
    aeron_socket_t socket,
    int join,
    const struct sockaddr_storage *src_addr,
    const struct sockaddr_storage *multicast_addr,
    const struct sockaddr_storage *interface_addr,
    unsigned int multicast_if_index)
{
    if (multicast_addr->ss_family == AF_INET6)
    {
        struct group_source_req gsr;
        memset(&gsr, 0, sizeof(gsr));
        gsr.gsr_interface = multicast_if_index;
        gsr.gsr_group = *multicast_addr;
        gsr.gsr_source = *src_addr;
        if (aeron_setsockopt(socket, IPPROTO_IPV6, join ? MCAST_JOIN_SOURCE_GROUP : MCAST_LEAVE_SOURCE_GROUP, &gsr, sizeof(gsr)) < 0)
        {
            aeron_set_err_from_last_err_code("%s ipv6 source-specific multicast failed", join ? "join" : "leave");
            return -1;
        }
    }
    else
    {
        struct ip_mreq_source mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_sourceaddr = ((const struct sockaddr_in *)src_addr)->sin_addr;
        mreq.imr_multiaddr = ((const struct sockaddr_in *)multicast_addr)->sin_addr;
        mreq.imr_interface = ((const struct sockaddr_in *)interface_addr)->sin_addr;
        if (aeron_setsockopt(socket, IPPROTO_IP, join ? IP_ADD_SOURCE_MEMBERSHIP : IP_DROP_SOURCE_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        {
            aeron_set_err_from_last_err_code("%s ipv4 source-specific multicast failed", join ? "join" : "leave");
            return -1;
        }
    }
    return 0;
}
