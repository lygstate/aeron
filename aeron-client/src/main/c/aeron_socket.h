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

#if defined(AERON_COMPILER_GCC)

#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

typedef int aeron_socket_t;

#elif defined(AERON_COMPILER_MSVC)
#if defined(sockaddr_storage_use_system)
    #include <WinSock2.h>
    #include <windows.h>
    #include <Ws2ipdef.h>
    #include <WS2tcpip.h>
    #include <Iphlpapi.h>
#else
    #include <basetsd.h>
    typedef unsigned long ULONG;
    typedef unsigned short USHORT;
    typedef int INT;
    typedef int socklen_t;
    struct sockaddr;
    typedef USHORT ADDRESS_FAMILY;
    typedef char CHAR;

    struct sockaddr_storage {
        ADDRESS_FAMILY ss_family;      // address family

        CHAR __ss_pad1[6];  // 6 byte pad, this is to make
                                    //   implementation specific pad up to
                                    //   alignment field that follows explicit
                                    //   in the data structure
        __int64 __ss_align;            // Field to force desired structure
        CHAR __ss_pad2[112];  // 112 byte pad to achieve desired size;
                                    //   _SS_MAXSIZE value minus size of
                                    //   ss_family, __ss_pad1, and
                                    //   __ss_align fields is 112
    };
#endif

    // SOCKET is uint64_t but we need a signed type to match the Linux version
    typedef INT_PTR aeron_socket_t;

struct iovec
{
    ULONG iov_len;
    void *iov_base;
};

// must match _WSAMSG
struct msghdr {
    void *msg_name;
    INT msg_namelen;
    struct iovec *msg_iov;
    ULONG msg_iovlen;
    ULONG msg_controllen;
    void* msg_control;
    ULONG msg_flags;
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
typedef SSIZE_T ssize_t;

ssize_t recvmsg(aeron_socket_t fd, struct msghdr *msghdr, int flags);
ssize_t sendmsg(aeron_socket_t fd, struct msghdr *msghdr, int flags);
int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#else
#error Unsupported platform!
#endif

int set_socket_non_blocking(aeron_socket_t fd);

aeron_socket_t aeron_socket(int domain, int type, int protocol);

void aeron_close_socket(aeron_socket_t socket);

void aeron_net_init();

int aeron_getsockopt(aeron_socket_t fd, int level, int optname, void *optval, socklen_t *optlen);

int aeron_setsockopt(aeron_socket_t fd, int level, int optname, const void *optval, socklen_t optlen);

#endif //AERON_SOCKET_H
