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

#include <stdint.h>
#include <stdbool.h>
#include "util/aeron_platform.h"

#if defined(AERON_OS_POSIX)

#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

typedef int aeron_socket_t;

#elif defined(AERON_OS_WIN32)
#if !defined(_INC_WINDOWS)

#define POLLRDNORM  0x0100
#define POLLRDBAND  0x0200
#define POLLIN      (POLLRDNORM | POLLRDBAND)
#define POLLPRI     0x0400

#define POLLWRNORM  0x0010
#define POLLOUT     (POLLWRNORM)
#define POLLWRBAND  0x0020

#define POLLERR     0x0001
#define POLLHUP     0x0002
#define POLLNVAL    0x0004

/* IP in string version, from ws2ipdef.h */
#define INET_ADDRSTRLEN  22
#define INET6_ADDRSTRLEN 65

//
// Although AF_UNSPEC is defined for backwards compatibility, using
// AF_UNSPEC for the "af" parameter when creating a socket is STRONGLY
// DISCOURAGED.  The interpretation of the "protocol" parameter
// depends on the actual address family chosen.  As environments grow
// to include more and more address families that use overlapping
// protocol values there is more and more chance of choosing an
// undesired address family when AF_UNSPEC is used.
//
#define AF_UNSPEC       0               // unspecified
#define AF_UNIX         1               // local to host (pipes, portals)
#define AF_INET         2               // internetwork: UDP, TCP, etc.
#define AF_IMPLINK      3               // arpanet imp addresses
#define AF_PUP          4               // pup protocols: e.g. BSP
#define AF_CHAOS        5               // mit CHAOS protocols
#define AF_NS           6               // XEROX NS protocols
#define AF_IPX          AF_NS           // IPX protocols: IPX, SPX, etc.
#define AF_ISO          7               // ISO protocols
#define AF_OSI          AF_ISO          // OSI is ISO
#define AF_ECMA         8               // european computer manufacturers
#define AF_DATAKIT      9               // datakit protocols
#define AF_CCITT        10              // CCITT protocols, X.25 etc
#define AF_SNA          11              // IBM SNA
#define AF_DECnet       12              // DECnet
#define AF_DLI          13              // Direct data link interface
#define AF_LAT          14              // LAT
#define AF_HYLINK       15              // NSC Hyperchannel
#define AF_APPLETALK    16              // AppleTalk
#define AF_NETBIOS      17              // NetBios-style addresses
#define AF_VOICEVIEW    18              // VoiceView
#define AF_FIREFOX      19              // Protocols from Firefox
#define AF_UNKNOWN1     20              // Somebody is using this!
#define AF_BAN          21              // Banyan
#define AF_ATM          22              // Native ATM Services
#define AF_INET6        23              // Internetwork Version 6
#define AF_CLUSTER      24              // Microsoft Wolfpack
#define AF_12844        25              // IEEE 1284.4 WG AF
#define AF_IRDA         26              // IrDA
#define AF_NETDES       28              // Network Designers OSI & gateway

#define AF_TCNPROCESS   29
#define AF_TCNMESSAGE   30
#define AF_ICLFXBM      31

#define AF_BTH          32              // Bluetooth RFCOMM/L2CAP protocols
#define AF_LINK         33
#define AF_HYPERV       34

//
// Socket types.
//

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3
#define SOCK_RDM        4
#define SOCK_SEQPACKET  5

//
// Define a level for socket I/O controls in the same numbering space as
// IPPROTO_TCP, IPPROTO_IP, etc.
//

#define SOL_SOCKET 0xffff

//
// Define socket-level options.
//

#define SO_DEBUG        0x0001      // turn on debugging info recording
#define SO_ACCEPTCONN   0x0002      // socket has had listen()
#define SO_REUSEADDR    0x0004      // allow local address reuse
#define SO_KEEPALIVE    0x0008      // keep connections alive
#define SO_DONTROUTE    0x0010      // just use interface addresses
#define SO_BROADCAST    0x0020      // permit sending of broadcast msgs
#define SO_USELOOPBACK  0x0040      // bypass hardware when possible
#define SO_LINGER       0x0080      // linger on close if data present
#define SO_OOBINLINE    0x0100      // leave received OOB data in line

#define SO_DONTLINGER   (int)(~SO_LINGER)
#define SO_EXCLUSIVEADDRUSE \
    ((int)(~SO_REUSEADDR))          // disallow local address reuse

#define SO_SNDBUF       0x1001      // send buffer size
#define SO_RCVBUF       0x1002      // receive buffer size
#define SO_SNDLOWAT     0x1003      // send low-water mark
#define SO_RCVLOWAT     0x1004      // receive low-water mark
#define SO_SNDTIMEO     0x1005      // send timeout
#define SO_RCVTIMEO     0x1006      // receive timeout
#define SO_ERROR        0x1007      // get error status and clear
#define SO_TYPE         0x1008      // get socket type
#define SO_BSP_STATE    0x1009      // get socket 5-tuple state

#define SO_GROUP_ID     0x2001      // ID of a socket group
#define SO_GROUP_PRIORITY 0x2002    // the relative priority within a group
#define SO_MAX_MSG_SIZE 0x2003      // maximum message size

#define SO_CONDITIONAL_ACCEPT 0x3002 // enable true conditional accept:
                                    // connection is not ack-ed to the
                                    // other side until conditional
                                    // function returns CF_ACCEPT
#define SO_PAUSE_ACCEPT 0x3003      // pause accepting new connections
#define SO_COMPARTMENT_ID 0x3004    // get/set the compartment for a socket
#if (AERON_OS_WIN32_WINNT >= 0x0600)
#define SO_RANDOMIZE_PORT 0x3005    // randomize assignment of wildcard ports
#define SO_PORT_SCALABILITY 0x3006  // enable port scalability
#define SO_REUSE_UNICASTPORT 0x3007 // defer ephemeral port allocation for
                                    // outbound connections
#define SO_REUSE_MULTICASTPORT 0x3008 // enable port reuse and disable unicast
                                    //reception.
#define SO_MSG_SEGMENT_SIZE 0x300C  // Segment sends into datagrams of length
                                    // MSG_SEGMENT_SIZE. The final datagram is
                                    // less than or equal to MSG_SEGMENT_SIZE.
#endif //(AERON_OS_WIN32_WINNT >= 0x0600)

#define IP_DEFAULT_MULTICAST_TTL   1    /* normally limit m'casts to 1 hop  */
#define IP_DEFAULT_MULTICAST_LOOP  1    /* normally hear sends if a member  */
#define IP_MAX_MEMBERSHIPS         20   /* per socket; must fit in one mbuf */

#define INADDR_ANY              (unsigned long)0x00000000

//
// Options to use with [gs]etsockopt at the IPPROTO_IPV6 level.
// These are specified in RFCs 3493 and 3542.
// The values should be consistent with the IPv6 equivalents.
//
#define IPV6_HOPOPTS           1 // Set/get IPv6 hop-by-hop options.
#define IPV6_HDRINCL           2 // Header is included with data.
#define IPV6_UNICAST_HOPS      4 // IP unicast hop limit.
#define IPV6_MULTICAST_IF      9 // IP multicast interface.
#define IPV6_MULTICAST_HOPS   10 // IP multicast hop limit.
#define IPV6_MULTICAST_LOOP   11 // IP multicast loopback.
#define IPV6_ADD_MEMBERSHIP   12 // Add an IP group membership.
#define IPV6_JOIN_GROUP       IPV6_ADD_MEMBERSHIP
#define IPV6_DROP_MEMBERSHIP  13 // Drop an IP group membership.
#define IPV6_LEAVE_GROUP      IPV6_DROP_MEMBERSHIP
#define IPV6_DONTFRAG         14 // Don't fragment IP datagrams.
#define IPV6_PKTINFO          19 // Receive packet information.
#define IPV6_HOPLIMIT         21 // Receive packet hop limit.
#define IPV6_PROTECTION_LEVEL 23 // Set/get IPv6 protection level.
#define IPV6_RECVIF           24 // Receive arrival interface.
#define IPV6_RECVDSTADDR      25 // Receive destination address.
#define IPV6_CHECKSUM         26 // Offset to checksum for raw IP socket send.
#define IPV6_V6ONLY           27 // Treat wildcard bind as AF_INET6-only.
#define IPV6_IFLIST           28 // Enable/Disable an interface list.
#define IPV6_ADD_IFLIST       29 // Add an interface list entry.
#define IPV6_DEL_IFLIST       30 // Delete an interface list entry.
#define IPV6_UNICAST_IF       31 // IP unicast interface.
#define IPV6_RTHDR            32 // Set/get IPv6 routing header.
#define IPV6_GET_IFLIST       33 // Get an interface list.
#define IPV6_RECVRTHDR        38 // Receive the routing header.
#define IPV6_TCLASS           39 // Packet traffic class.
#define IPV6_RECVTCLASS       40 // Receive packet traffic class.
#define IPV6_ECN              50 // Receive ECN codepoints in the IP header.
#define IPV6_PKTINFO_EX       51 // Receive extended packet information.
#define IPV6_WFP_REDIRECT_RECORDS   60 // WFP's Connection Redirect Records
#define IPV6_WFP_REDIRECT_CONTEXT   70 // WFP's Connection Redirect Context
#define IPV6_MTU_DISCOVER           71 // Set/get path MTU discover state.
#define IPV6_MTU                    72 // Get path MTU.
#define IPV6_NRT_INTERFACE          74 // Set NRT interface constraint (outbound).
#define IPV6_RECVERR                75 // Receive ICMPv6 errors.


//
// N.B. required for backwards compatability to support 0 = IP for the
// level argument to get/setsockopt.
//
#define IPPROTO_IP              0

//
// Protocols.  The IPv6 defines are specified in RFC 2292.
//
typedef enum {
    IPPROTO_HOPOPTS       = 0,  // IPv6 Hop-by-Hop options
    IPPROTO_ICMP          = 1,
    IPPROTO_IGMP          = 2,
    IPPROTO_GGP           = 3,
    IPPROTO_IPV4          = 4,
    IPPROTO_ST            = 5,
    IPPROTO_TCP           = 6,
    IPPROTO_CBT           = 7,
    IPPROTO_EGP           = 8,
    IPPROTO_IGP           = 9,
    IPPROTO_PUP           = 12,
    IPPROTO_UDP           = 17,
    IPPROTO_IDP           = 22,
    IPPROTO_RDP           = 27,
    IPPROTO_IPV6          = 41, // IPv6 header
    IPPROTO_ROUTING       = 43, // IPv6 Routing header
    IPPROTO_FRAGMENT      = 44, // IPv6 fragmentation header
    IPPROTO_ESP           = 50, // encapsulating security payload
    IPPROTO_AH            = 51, // authentication header
    IPPROTO_ICMPV6        = 58, // ICMPv6
    IPPROTO_NONE          = 59, // IPv6 no next header
    IPPROTO_DSTOPTS       = 60, // IPv6 Destination options
    IPPROTO_ND            = 77,
    IPPROTO_ICLFXBM       = 78,
    IPPROTO_PIM           = 103,
    IPPROTO_PGM           = 113,
    IPPROTO_L2TP          = 115,
    IPPROTO_SCTP          = 132,
    IPPROTO_RAW           = 255,

    IPPROTO_MAX           = 256,
//
//  These are reserved for internal use by Windows.
//
    IPPROTO_RESERVED_RAW  = 257,
    IPPROTO_RESERVED_IPSEC  = 258,
    IPPROTO_RESERVED_IPSECOFFLOAD  = 259,
    IPPROTO_RESERVED_WNV = 260,
    IPPROTO_RESERVED_MAX  = 261
} IPPROTO;

//
// Options to use with [gs]etsockopt at the IPPROTO_IP level.
// The values should be consistent with the IPv6 equivalents.
//
#define IP_OPTIONS                 1 // Set/get IP options.
#define IP_HDRINCL                 2 // Header is included with data.
#define IP_TOS                     3 // IP type of service.
#define IP_TTL                     4 // IP TTL (hop limit).
#define IP_MULTICAST_IF            9 // IP multicast interface.
#define IP_MULTICAST_TTL          10 // IP multicast TTL (hop limit).
#define IP_MULTICAST_LOOP         11 // IP multicast loopback.
#define IP_ADD_MEMBERSHIP         12 // Add an IP group membership.
#define IP_DROP_MEMBERSHIP        13 // Drop an IP group membership.
#define IP_DONTFRAGMENT           14 // Don't fragment IP datagrams.
#define IP_ADD_SOURCE_MEMBERSHIP  15 // Join IP group/source.
#define IP_DROP_SOURCE_MEMBERSHIP 16 // Leave IP group/source.
#define IP_BLOCK_SOURCE           17 // Block IP group/source.
#define IP_UNBLOCK_SOURCE         18 // Unblock IP group/source.
#define IP_PKTINFO                19 // Receive packet information.
#define IP_HOPLIMIT               21 // Receive packet hop limit.
#define IP_RECVTTL                21 // Receive packet Time To Live (TTL).
#define IP_RECEIVE_BROADCAST      22 // Allow/block broadcast reception.
#define IP_RECVIF                 24 // Receive arrival interface.
#define IP_RECVDSTADDR            25 // Receive destination address.
#define IP_IFLIST                 28 // Enable/Disable an interface list.
#define IP_ADD_IFLIST             29 // Add an interface list entry.
#define IP_DEL_IFLIST             30 // Delete an interface list entry.
#define IP_UNICAST_IF             31 // IP unicast interface.
#define IP_RTHDR                  32 // Set/get IPv6 routing header.
#define IP_GET_IFLIST             33 // Get an interface list.
#define IP_RECVRTHDR              38 // Receive the routing header.
#define IP_TCLASS                 39 // Packet traffic class.
#define IP_RECVTCLASS             40 // Receive packet traffic class.
#define IP_RECVTOS                40 // Receive packet Type Of Service (TOS).
#define IP_ORIGINAL_ARRIVAL_IF    47 // Original Arrival Interface Index.
#define IP_ECN                    50 // Receive ECN codepoints in the IP header.
#define IP_PKTINFO_EX             51 // Receive extended packet information.
#define IP_WFP_REDIRECT_RECORDS   60 // WFP's Connection Redirect Records.
#define IP_WFP_REDIRECT_CONTEXT   70 // WFP's Connection Redirect Context.
#define IP_MTU_DISCOVER           71 // Set/get path MTU discover state.
#define IP_MTU                    73 // Get path MTU.
#define IP_NRT_INTERFACE          74 // Set NRT interface constraint (outbound).
#define IP_RECVERR                75 // Receive ICMP errors.

#define IFF_UP              0x00000001 // Interface is up.
#define IFF_BROADCAST       0x00000002 // Broadcast is  supported.
#define IFF_LOOPBACK        0x00000004 // This is loopback interface.
#define IFF_POINTTOPOINT    0x00000008 // This is point-to-point interface.
#define IFF_MULTICAST       0x00000010 // Multicast is supported.

//
// Protocol independent multicast source filter options.
//
#define MCAST_JOIN_GROUP            41	// Join all sources for a group.
#define MCAST_LEAVE_GROUP           42  // Drop all sources for a group.
#define MCAST_BLOCK_SOURCE          43	// Block IP group/source.
#define MCAST_UNBLOCK_SOURCE        44	// Unblock IP group/source.
#define MCAST_JOIN_SOURCE_GROUP     45	// Join IP group/source.
#define MCAST_LEAVE_SOURCE_GROUP    46	// Leave IP group/source.

typedef int socklen_t;

struct sockaddr
{
    unsigned short sa_family; /* address family */
    char sa_data[14];         /* up to 14 bytes of direct address */
};

struct sockaddr_storage
{
    unsigned short ss_family; /* address family */

    char __ss_pad1[6];   /* 6 byte pad, this is to make
                            implementation specific pad up to 
                            alignment field that follows explicit
                            in the data structure */
    __int64 __ss_align;  /* Field to force desired structure */
    char __ss_pad2[112]; /* 112 byte pad to achieve desired size;
                                    //   _SS_MAXSIZE value minus size of
                                    //   ss_family, __ss_pad1, and
                                    //   __ss_align fields is 112 */
};

typedef unsigned long in_addr_t;

struct in_addr {
        union {
                struct { unsigned char s_b1,s_b2,s_b3,s_b4; } S_un_b;
                struct { unsigned short s_w1,s_w2; } S_un_w;
                unsigned long S_addr;
        } S_un;
#define s_addr  S_un.S_addr /* can be used for most tcp & ip code */
#define s_host  S_un.S_un_b.s_b2    // host on imp
#define s_net   S_un.S_un_b.s_b1    // network
#define s_imp   S_un.S_un_w.s_w2    // imp
#define s_impno S_un.S_un_b.s_b4    // imp #
#define s_lh    S_un.S_un_b.s_b3    // logical host
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

/*
 * Argument structure for IP_ADD_MEMBERSHIP and IP_DROP_MEMBERSHIP.
 */
struct ip_mreq {
    struct in_addr imr_multiaddr;  /* IP multicast address of group */
    struct in_addr imr_interface;  /* local IP address of interface */
};

typedef struct {
    union {
        struct {
            unsigned long Zone : 28;
            unsigned long Level : 4;
        };
        unsigned long Value;
    };
} SCOPE_ID;

struct in6_addr {
    union {
        unsigned char       Byte[16];
        unsigned short      Word[8];
    } u;
};

struct sockaddr_in6 {
    unsigned short sin6_family; // AF_INET6.
    unsigned short sin6_port;           // Transport level port number.
    unsigned long  sin6_flowinfo;       // IPv6 flow information.
    struct in6_addr sin6_addr;         // IPv6 address.
    union {
        unsigned long sin6_scope_id;     // Set of interfaces for a scope.
        SCOPE_ID sin6_scope_struct;
    };
};

struct pollfd {
    intptr_t  fd;
    short events;
    short revents;
};

struct ipv6_mreq {
    struct in6_addr ipv6mr_multiaddr;  // IPv6 multicast address.
    unsigned long ipv6mr_interface;     // Interface index.
};

struct ip_mreq_source {
    struct in_addr imr_multiaddr;  // IP multicast address of group.
    struct in_addr imr_sourceaddr; // IP address of source.
    struct in_addr imr_interface;  // Local IP address of interface.
};

struct group_source_req {
    unsigned long gsr_interface;        // Interface index.
    struct sockaddr_storage gsr_group; // Group address.
    struct sockaddr_storage gsr_source; // Source address.
};

#endif

/* SOCKET is uint64_t but we need a signed type to match the Linux version */
typedef intptr_t aeron_socket_t;

struct iovec
{
    unsigned long iov_len;
    void *iov_base;
};

// must match _WSAMSG
struct msghdr {
    void *msg_name;
    int msg_namelen;
    struct iovec *msg_iov;
    unsigned long msg_iovlen;
    unsigned long msg_controllen;
    void *msg_control;
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
    }
    ifa_ifu;

# ifndef ifa_broadaddr
#  define ifa_broadaddr      ifa_ifu.ifu_broadaddr
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

const char *aeron_inet_ntop(int af, const void *src, char *dst, socklen_t size);
int aeron_inet_pton(int af, const char *src, void *dst);
uint32_t aeron_htonl(uint32_t hostlong);
uint16_t aeron_htons(uint16_t hostshort);
uint32_t aeron_ntohl(uint32_t netlong);
uint16_t aeron_ntohs(uint16_t netshort);

#if !defined(_INC_WINDOWS)
#define inet_ntop aeron_inet_ntop
#define inet_pton aeron_inet_pton
#define htonl aeron_htonl
#define htons aeron_htons
#define ntohl aeron_ntohl
#define ntohs aeron_ntohs
#endif

#else
#error Unsupported platform!
#endif

struct aeron_mmsghdr
{
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

#define AERON_ADDR_LEN(a) (AF_INET6 == (a)->ss_family ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))

bool aeron_in6_is_addr_linklocal(const struct in6_addr *a);

int aeron_socket_addr_to_string(const struct sockaddr_storage *addr, char* buf, socklen_t buf_size);

uint16_t aeron_socket_addr_port(const struct sockaddr_storage *addr);

unsigned int aeron_if_nametoindex(const char *name);

struct in6_addr aeron_in6addr_any();

int aeron_bind(aeron_socket_t sockfd, const struct sockaddr *addr, socklen_t addrlen);

int aeron_getsockname(aeron_socket_t sockfd, struct sockaddr *addr, socklen_t *addrlen);

int aeron_gethostname(char *name, size_t len);

int aeron_ip_addr_resolver(const char *host, const char *service, struct sockaddr_storage *sockaddr, int family_hint, int protocol);

bool aeron_is_addr_multicast(struct sockaddr_storage *addr);

typedef void (*aeron_udp_recv_func_t)(
    void* context,
    uint8_t *buffer,
    size_t length,
    struct sockaddr_storage *addr);

int aeron_udp_recvmmsg(
    aeron_socket_t fd,
    void *context,
    struct aeron_mmsghdr *msgvec,
    size_t count,
    int *bytes_rcved,
    aeron_udp_recv_func_t recv_func);

int aeron_udp_sendmmsg(
    aeron_socket_t fd,
    struct aeron_mmsghdr *msgvec,
    size_t count,
    int *bytes_sent);

int set_socket_non_blocking(aeron_socket_t fd);

aeron_socket_t aeron_socket(int domain, int type, int protocol);

void aeron_close_socket(aeron_socket_t socket);

void aeron_net_init();

int aeron_getsockopt(aeron_socket_t fd, int level, int optname, void *optval, socklen_t *optlen);

int aeron_setsockopt(aeron_socket_t fd, int level, int optname, const void *optval, socklen_t optlen);

#endif //AERON_SOCKET_H
