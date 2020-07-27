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

#include "util/aeron_platform.h"
#include "aeron_socket.h"

#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include "util/aeron_error.h"
#include "util/aeron_netutil.h"
#include "aeron_udp_channel_transport.h"

int aeron_udp_channel_transport_init(
    aeron_udp_channel_transport_t *transport,
    struct sockaddr_storage *bind_addr,
    struct sockaddr_storage *multicast_if_addr,
    unsigned int multicast_if_index,
    uint8_t ttl,
    size_t socket_rcvbuf,
    size_t socket_sndbuf,
    aeron_driver_context_t *context,
    aeron_udp_channel_transport_affinity_t affinity)
{
    bool is_multicast = aeron_is_addr_multicast(bind_addr);
    transport->fd = -1;
    transport->fd_send = -1;
    transport->bindings_clientd = NULL;
    for (size_t i = 0; i < AERON_UDP_CHANNEL_TRANSPORT_MAX_INTERCEPTORS; i++)
    {
        transport->interceptor_clientds[i] = NULL;
    }

    if (!is_multicast)
    {
        if (aeron_udp_create_conn(&transport->fd,
            AERON_SOCKET_TRAN_QOS_UC,
            socket_rcvbuf,
            socket_sndbuf,
            bind_addr, multicast_if_addr, multicast_if_index,
            ttl, 0, 0, 0) < 0)
        {
            goto error;
        }
        transport->fd_send = transport->fd;
    }
    else
    {
        if (aeron_udp_create_conn(&transport->fd,
            AERON_SOCKET_TRAN_QOS_RECV_MC,
            socket_rcvbuf,
            socket_sndbuf,
            bind_addr, multicast_if_addr, multicast_if_index,
            0, 0, 0, 0) < 0)
        {
            goto error;
        }

        if (aeron_joinleave_asm_mcgroup(transport->fd, 1, bind_addr, multicast_if_addr, multicast_if_index) < 0)
        {
            goto error;
        }

        if (aeron_udp_create_conn(&transport->fd_send,
            AERON_SOCKET_TRAN_QOS_XMIT,
            socket_rcvbuf,
            socket_sndbuf,
            multicast_if_addr, multicast_if_addr, multicast_if_index,
            ttl, 1, 0, 0) < 0)
        {
            goto error;
        }
    }

    return 0;

    error:
        aeron_udp_channel_transport_close(transport);
        return -1;
}

int aeron_udp_channel_transport_close(aeron_udp_channel_transport_t *transport)
{
    if (transport->fd != -1)
    {
        aeron_close_socket(transport->fd);
    }

    if (transport->fd_send != -1 && transport->fd != transport->fd_send)
    {
        aeron_close_socket(transport->fd_send);
    }
    transport->fd = -1;
    transport->fd_send = -1;

    return 0;
}

struct aeron_udp_channel_transport_recvmmsg_context
{
    aeron_udp_channel_transport_t *transport;
    aeron_udp_transport_recv_func_t recv_func;
    void *clientd;
};

void aeron_udp_channel_transport_recvmmsg_callback(
    void* context,
    uint8_t *buffer,
    size_t length,
    struct sockaddr_storage *addr)
{
    struct aeron_udp_channel_transport_recvmmsg_context *recvmmsg_context =
        (struct aeron_udp_channel_transport_recvmmsg_context *)context;
    recvmmsg_context->recv_func(
        recvmmsg_context->transport->data_paths,
        recvmmsg_context->transport,
        recvmmsg_context->clientd,
        recvmmsg_context->transport->dispatch_clientd,
        recvmmsg_context->transport->destination_clientd,
        buffer,
        length,
        addr);
}

int aeron_udp_channel_transport_recvmmsg(
    aeron_udp_channel_transport_t *transport,
    struct aeron_mmsghdr *msgvec,
    size_t vlen,
    int64_t *bytes_rcved,
    aeron_udp_transport_recv_func_t recv_func,
    void *clientd)
{
    int tmp_bytes_rcved = -1;
    struct aeron_udp_channel_transport_recvmmsg_context context;
    context.transport = transport;
    context.recv_func = recv_func;
    context.clientd = clientd;
    int recvmmsg_result = aeron_udp_recvmmsg(transport->fd, &context, msgvec, vlen, &tmp_bytes_rcved, aeron_udp_channel_transport_recvmmsg_callback);
    *bytes_rcved = tmp_bytes_rcved;
    return recvmmsg_result;
}

int aeron_udp_channel_transport_sendmmsg(
    aeron_udp_channel_data_paths_t *data_paths,
    aeron_udp_channel_transport_t *transport,
    struct aeron_mmsghdr *msgvec,
    size_t vlen)
{
    int bytes_sent = -1;
    int sendmmsg_result = aeron_udp_sendmmsg(transport->fd_send, msgvec, vlen, &bytes_sent);
    return sendmmsg_result;
}

int aeron_udp_channel_transport_get_so_rcvbuf(aeron_udp_channel_transport_t *transport, size_t *so_rcvbuf)
{
    socklen_t len = sizeof(size_t);

    if (aeron_getsockopt(transport->fd, SOL_SOCKET, SO_RCVBUF, so_rcvbuf, &len) < 0)
    {
        aeron_set_err_from_last_err_code("getsockopt(SO_RCVBUF) %s:%d", __FILE__, __LINE__);
        return -1;
    }

    return 0;
}

int aeron_udp_channel_transport_bind_addr_and_port(
    aeron_udp_channel_transport_t *transport, char *buffer, size_t length)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    if (aeron_getsockname(transport->fd, (struct sockaddr *)&addr, &addr_len) < 0)
    {
        aeron_set_err_from_last_err_code("getsockname %s:%d", __FILE__, __LINE__);
        return -1;
    }

    return aeron_format_source_identity(buffer, length, &addr);
}

extern void *aeron_udp_channel_transport_get_interceptor_clientd(
    aeron_udp_channel_transport_t *transport, int interceptor_index);

extern void aeron_udp_channel_transport_set_interceptor_clientd(
    aeron_udp_channel_transport_t *transport, int interceptor_index, void *clientd);
