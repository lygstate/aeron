#if defined(__linux__)
#define _BSD_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <aeron_socket.h>
#include <util/aeron_netutil.h>
#include <concurrent/aeron_thread.h>

void send_single(aeron_socket_t send_fd, struct sockaddr_storage bind_addr, const char *interface_addr)
{
    char buf[1024];
    int i = 0;
    struct aeron_mmsghdr msgvec[1];
    struct iovec msg_iov;
    sprintf(buf, "Hello, the world:%s", interface_addr);
    msg_iov.iov_base = buf;
    msg_iov.iov_len = (unsigned long)strlen((const char *)msg_iov.iov_base);

    {
        msgvec[i].msg_hdr.msg_name = &bind_addr;
        msgvec[i].msg_hdr.msg_namelen = sizeof(bind_addr);
        msgvec[i].msg_hdr.msg_iov = &msg_iov;
        msgvec[i].msg_hdr.msg_iovlen = 1;
        msgvec[i].msg_hdr.msg_flags = 0;
        msgvec[i].msg_hdr.msg_control = NULL;
        msgvec[i].msg_hdr.msg_controllen = 0;
        msgvec[i].msg_len = 0;
    }

    int bytes_send;
    aeron_udp_sendmmsg(send_fd, msgvec, 1, &bytes_send);
    printf("Sending things %d\n", bytes_send);
}

void recv_callback(
    void *context,
    uint8_t *buffer,
    size_t length,
    struct sockaddr_storage *addr)
{
    char socket_addr_buf[AERON_NETUTIL_FORMATTED_MAX_LENGTH];
    aeron_socket_addr_to_string(addr, socket_addr_buf, sizeof(socket_addr_buf));
    printf("The buffer is:%s from:(%s:%d)\n", buffer, socket_addr_buf, aeron_socket_addr_port(addr));
}

char recv_buf[65536];
int recv_single(aeron_socket_t recv_fd)
{
    struct iovec msg_iov;
    msg_iov.iov_base = recv_buf;
    msg_iov.iov_len = sizeof(recv_buf);
    memset(recv_buf, 0, sizeof(recv_buf));
    struct aeron_mmsghdr msgvec[1];
    struct sockaddr_storage addr_from;
    int i = 0;
    int bytes_recved;
    {
        msgvec[i].msg_hdr.msg_name = &addr_from;
        msgvec[i].msg_hdr.msg_namelen = sizeof(addr_from);
        msgvec[i].msg_hdr.msg_iov = &msg_iov;
        msgvec[i].msg_hdr.msg_iovlen = 1;
        msgvec[i].msg_hdr.msg_flags = 0;
        msgvec[i].msg_hdr.msg_control = NULL;
        msgvec[i].msg_hdr.msg_controllen = 0;
        msgvec[i].msg_len = 0;
    }

    aeron_udp_recvmmsg(recv_fd, NULL, msgvec, 1, &bytes_recved, recv_callback);
    return bytes_recved;
}

aeron_socket_t recv_fd;
aeron_socket_t send_fd;
char socket_addr_buf[AERON_NETUTIL_FORMATTED_MAX_LENGTH];
struct sockaddr_storage interface_addr;
struct sockaddr_storage bind_addr;

void init_udp_multicast()
{
    int socket_rcvbuf = 128 * 1024;
    int socket_sndbuf = 128 * 1024;
    unsigned int if_index;
    int ttl = 1;
    aeron_ip_addr_resolver("239.255.0.1", "29375", &bind_addr, AF_INET, IPPROTO_UDP);
    aeron_find_interface("192.168.199.0/22", (struct sockaddr_storage *)&interface_addr, &if_index);
    if (aeron_udp_create_conn(&recv_fd,
                              AERON_SOCKET_TRAN_QOS_RECV_MC,
                              socket_rcvbuf,
                              socket_sndbuf,
                              &bind_addr, &interface_addr, if_index,
                              0, 0, 0, 0) < 0)
    {
    }

    if (aeron_joinleave_asm_mcgroup(recv_fd, 1, &bind_addr, &interface_addr, if_index) < 0)
    {
    }

    if (aeron_udp_create_conn(&send_fd,
                              AERON_SOCKET_TRAN_QOS_XMIT,
                              socket_rcvbuf,
                              socket_sndbuf,
                              &interface_addr, &interface_addr, if_index,
                              ttl, 1, 0, 0) < 0)
    {
    }
    aeron_socket_addr_to_string(&bind_addr, socket_addr_buf, sizeof(socket_addr_buf));
    printf("The multicast addrs is %s\n", socket_addr_buf);

    aeron_socket_addr_to_string(&interface_addr, socket_addr_buf, sizeof(socket_addr_buf));
    printf("The interface addrs is %s\n", socket_addr_buf);
}

void udp_send_and_receive_multicast()
{
    send_single(send_fd, bind_addr, socket_addr_buf);
    for (;;)
    {
        if (recv_single(recv_fd) <= 0)
        {
            break;
        }
    }
}

aeron_socket_t uni_fd;
struct sockaddr_storage bind_addr_uni;
char socket_addr_buf_uni[AERON_NETUTIL_FORMATTED_MAX_LENGTH];

void init_udp_unicast()
{
    aeron_ip_addr_resolver("127.0.0.1", "33891", &bind_addr_uni, AF_INET, IPPROTO_UDP);
    int socket_rcvbuf = 128 * 1024;
    int socket_sndbuf = 128 * 1024;
    if (aeron_udp_create_conn(&uni_fd,
                              AERON_SOCKET_TRAN_QOS_UC,
                              socket_rcvbuf,
                              socket_sndbuf,
                              &bind_addr_uni, NULL, -1,
                              0, 0, 0, 0) < 0)
    {
    }
    aeron_socket_addr_to_string(&bind_addr_uni, socket_addr_buf_uni, sizeof(socket_addr_buf_uni));
    printf("The bind addr is %s\n", socket_addr_buf_uni);
}


void udp_send_and_receive_unicast()
{
    send_single(uni_fd, bind_addr_uni, socket_addr_buf_uni);
    for (;;)
    {
        if (recv_single(uni_fd) <= 0)
        {
            break;
        }
    }
}

void test_udp()
{
    init_udp_multicast();
    init_udp_unicast();
    for (;;)
    {
        udp_send_and_receive_multicast();
        udp_send_and_receive_unicast();
        aeron_micro_sleep(1000000);
    }
}

int main()
{
    test_udp();
    return 0;
}
