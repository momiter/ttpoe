// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef MODTTPOE_SOCKET_H
#define MODTTPOE_SOCKET_H

#include <linux/net.h>
#include <net/sock.h>

#include <ttp_socket.h>

#include "ttpoe.h"

enum ttp_sock_state {
    TTP_SS_INIT = 0,
    TTP_SS_BOUND,
    TTP_SS_CONNECTING,
    TTP_SS_ESTABLISHED,
    TTP_SS_CLOSED,
    TTP_SS_ERROR,
};

struct ttp_sock {
    struct sock sk;
    struct ttpoe_host_info target;
    u8 local_node[TTP_NODE_ADDR_LEN];
    u8 peer_node[TTP_NODE_ADDR_LEN];
    int ifindex;
    u8 vci;
    u64 kid;
    int state;
    int last_error;
    spinlock_t lock;
    wait_queue_head_t waitq;
    struct sk_buff_head rxq;
    struct sk_buff *reasm_skb;
    u32 reasm_total_len;
    u32 reasm_next_off;
};

extern struct proto ttp_proto;
extern struct proto_ops ttp_proto_ops;
extern int ttp_socket_family;

static inline struct ttp_sock *ttp_sk(const struct sock *sk)
{
    return (struct ttp_sock *)sk;
}

int ttp_create(struct net *net, struct socket *sock, int protocol, int kern);
int ttp_socket_init(void);
void ttp_socket_exit(void);

int ttpoe_socket_payload_rx(u64 kid, const u8 *data, u16 nl);
void ttpoe_socket_fsm_event(struct ttp_fsm_event *ev, int rs, int ns);
void ttpoe_socket_link_error(u64 kid, int err);

#endif
