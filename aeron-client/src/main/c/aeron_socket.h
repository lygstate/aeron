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

#ifndef AERON_SOCKET_H
#define AERON_SOCKET_H

#include <util/aeron_platform.h>
#include <stdint.h>
#include <stdbool.h>

/* IP in string version */
#define AERON_NETUTIL_FORMATTED_MAX_LENGTH 128

#if defined(AERON_COMPILER_GCC)

#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

typedef int aeron_socket_t;
#define AERON_AF_INET6 AF_INET6

#elif defined(AERON_COMPILER_MSVC)
    typedef int socklen_t;
    struct sockaddr;

    struct sockaddr_storage {
        unsigned short ss_family;      /* address family */

        char __ss_pad1[6];  /* 6 byte pad, this is to make
                            implementation specific pad up to 
                            alignment field that follows explicit
                            in the data structure */
        __int64 __ss_align;   /* Field to force desired structure */
        char __ss_pad2[112];  /* 112 byte pad to achieve desired size;
                                    //   _SS_MAXSIZE value minus size of
                                    //   ss_family, __ss_pad1, and
                                    //   __ss_align fields is 112 */
    };

    /* SOCKET is uint64_t but we need a signed type to match the Linux version */
    typedef intptr_t aeron_socket_t;

#define AERON_AF_INET6        23              /* Internetwork Version 6 */
#define AERON_ADDR_LEN_IN6 128
#define AERON_ADDR_LEN_IN4 66

struct iovec
{
    unsigned long iov_len;
    void *iov_base;
};

/* must match WSAMSG */
struct msghdr {
    void *msg_name;
    int msg_namelen;
    struct iovec *msg_iov;
    unsigned long msg_iovlen;
    unsigned long msg_controllen;
    void* msg_control;
    unsigned long msg_flags;
};

struct ifaddrs
{
    struct ifaddrs *ifa_next;
    char *ifa_name;
    unsigned int ifa_flags;

    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_netmask;
    union
    {
        struct sockaddr *ifu_broadaddr;
        struct sockaddr *ifu_dstaddr;
    } ifa_ifu;

# ifndef ifa_broadaddr
#  define ifa_broadaddr        ifa_ifu.ifu_broadaddr
# endif
# ifndef ifa_dstaddr
#  define ifa_dstaddr        ifa_ifu.ifu_dstaddr
# endif

    void *ifa_data;
};

int getifaddrs(struct ifaddrs **ifap);
void freeifaddrs(struct ifaddrs *ifa);

typedef unsigned long int nfds_t;
typedef intptr_t ssize_t;

ssize_t recvmsg(aeron_socket_t fd, struct msghdr *msghdr, int flags);
ssize_t sendmsg(aeron_socket_t fd, struct msghdr *msghdr, int flags);
int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#else
#error Unsupported platform!
#endif

#define AERON_ADDR_LEN(a) (AERON_AF_INET6 == (a)->ss_family ? AERON_ADDR_LEN_IN6 : AERON_ADDR_LEN_IN4

int set_socket_non_blocking(aeron_socket_t fd);

aeron_socket_t aeron_socket(int domain, int type, int protocol);

void aeron_close_socket(aeron_socket_t socket);

void aeron_net_init();
void aeron_net_term();

int aeron_getsockopt(aeron_socket_t fd, int level, int optname, void *optval, socklen_t *optlen);

int aeron_setsockopt(aeron_socket_t fd, int level, int optname, const void *optval, socklen_t optlen);

typedef int (*aeron_uri_hostname_resolver_func_t)
    (void *clientd, const char *host, struct addrinfo *hints, struct addrinfo **info);

typedef int (*aeron_getifaddrs_func_t)(struct ifaddrs **);

typedef void (*aeron_freeifaddrs_func_t)(struct ifaddrs *);

typedef int (*aeron_ifaddr_func_t)
    (void *clientd, const char *name, struct sockaddr *addr, struct sockaddr *netmask, unsigned int flags);

int aeron_ip_addr_resolver(const char *host, struct sockaddr_storage *sockaddr, int family_hint, int protocol);

int aeron_udp_port_resolver(const char *port_str, bool optional);

bool aeron_try_parse_ipv4(const char *host, struct sockaddr_storage *sockaddr);

int aeron_ipv4_addr_resolver(const char *host, int protocol, struct sockaddr_storage *sockaddr);

bool aeron_try_parse_ipv6(const char *host, struct sockaddr_storage *sockaddr);

int aeron_ipv6_addr_resolver(const char *host, int protocol, struct sockaddr_storage *sockaddr);

int aeron_lookup_interfaces(aeron_ifaddr_func_t func, void *clientd);

int aeron_lookup_interfaces_from_ifaddrs(aeron_ifaddr_func_t func, void *clientd, struct ifaddrs *ifaddrs);

void aeron_set_getifaddrs(aeron_getifaddrs_func_t get_func, aeron_freeifaddrs_func_t free_func);

int aeron_interface_parse_and_resolve(const char *interface_str, struct sockaddr_storage *sockaddr, size_t *prefixlen);

void aeron_set_ipv4_wildcard_host_and_port(struct sockaddr_storage *sockaddr);

bool aeron_ipv4_does_prefix_match(struct in_addr *in_addr1, struct in_addr *in_addr2, size_t prefixlen);

bool aeron_ipv6_does_prefix_match(struct in6_addr *in6_addr1, struct in6_addr *in6_addr2, size_t prefixlen);

size_t aeron_ipv4_netmask_to_prefixlen(struct in_addr *netmask);

size_t aeron_ipv6_netmask_to_prefixlen(struct in6_addr *netmask);

int aeron_find_interface(const char *interface_str, struct sockaddr_storage *if_addr, unsigned int *if_index);

int aeron_find_unicast_interface(
    int family, const char *interface_str, struct sockaddr_storage *interface_addr, unsigned int *interface_index);

bool aeron_is_addr_multicast(struct sockaddr_storage *addr);

bool aeron_is_wildcard_addr(struct sockaddr_storage *addr);

bool aeron_is_wildcard_port(struct sockaddr_storage *addr);

int aeron_format_source_identity(char *buffer, size_t length, struct sockaddr_storage *addr);

int aeron_find_multicast_interface(
    int family, const char *interface_str, struct sockaddr_storage *interface_addr, unsigned int *interface_index);

#endif //AERON_SOCKET_H
