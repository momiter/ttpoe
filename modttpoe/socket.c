// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/uio.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/addrconf.h>
#include <net/ip.h>
#include <net/sock.h>

#include <ttp.h>
#include <ttp_socket.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "noc.h"
#include "socket.h"

#define TTP_SOCK_RXQ_LIMIT      128
#define TTP_CONNECT_TIMEOUT_MS  3000

static int ttp_sock_bind_tag(struct ttp_sock *tsk, u64 kid);
static void ttp_sock_unbind_tag(struct ttp_sock *tsk);
static void ttp_sock_set_state(struct ttp_sock *tsk, int state);
static void ttp_sock_set_error(struct ttp_sock *tsk, int err);

static int ttp_listen(struct socket *sock, int backlog)
{
    (void)sock;
    (void)backlog;
    return -EOPNOTSUPP;
}

static int ttp_sock_shutdown(struct socket *sock, int flags)
{
    (void)sock;
    (void)flags;
    return -EOPNOTSUPP;
}

static int ttp_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    (void)sock;
    (void)cmd;
    (void)arg;
    return -EOPNOTSUPP;
}

static int ttp_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
    (void)file;
    (void)sock;
    (void)vma;
    return -EOPNOTSUPP;
}

static int ttp_socketpair(struct socket *sock1, struct socket *sock2)
{
    (void)sock1;
    (void)sock2;
    return -EOPNOTSUPP;
}

static int ttp_accept(struct socket *sock, struct socket *newsock, int flags, bool kern)
{
    (void)sock;
    (void)newsock;
    (void)flags;
    (void)kern;
    return -EOPNOTSUPP;
}

static struct ttp_sock *ttp_sock_lookup_kid(u64 kid)
{
    struct ttp_link_tag *lt;
    struct ttp_sock *tsk = NULL;

    if (!kid) {
        return NULL;
    }

    lt = ttp_rbtree_tag_get(kid);
    if (!lt) {
        return NULL;
    }

    TTP_RUN_SPIN_LOCKED({
        if (lt->sock) {
            sock_hold(&lt->sock->sk);
            tsk = lt->sock;
        }
    });

    return tsk;
}

static void ttp_sock_put(struct ttp_sock *tsk)
{
    if (tsk) {
        sock_put(&tsk->sk);
    }
}

void ttpoe_socket_link_error(u64 kid, int err)
{
    struct ttp_sock *tsk;

    tsk = ttp_sock_lookup_kid(kid);
    if (!tsk) {
        return;
    }

    ttp_sock_set_error(tsk, err);
    ttp_sock_unbind_tag(tsk);
    ttp_sock_put(tsk);
}

static void ttp_sock_set_state(struct ttp_sock *tsk, int state)
{
    unsigned long flags;

    spin_lock_irqsave(&tsk->lock, flags);
    tsk->state = state;
    spin_unlock_irqrestore(&tsk->lock, flags);

    wake_up_interruptible(&tsk->waitq);
    if (sk_sleep(&tsk->sk)) {
        wake_up_interruptible_all(sk_sleep(&tsk->sk));
    }
}

static void ttp_sock_set_error(struct ttp_sock *tsk, int err)
{
    unsigned long flags;

    spin_lock_irqsave(&tsk->lock, flags);
    tsk->last_error = err;
    tsk->state = TTP_SS_ERROR;
    tsk->sk.sk_err = err;
    spin_unlock_irqrestore(&tsk->lock, flags);

    wake_up_interruptible(&tsk->waitq);
    if (sk_sleep(&tsk->sk)) {
        wake_up_interruptible_all(sk_sleep(&tsk->sk));
    }
}

static int ttp_sock_bind_tag(struct ttp_sock *tsk, u64 kid)
{
    struct ttp_link_tag *lt;
    int rc = 0;

    lt = ttp_rbtree_tag_get(kid);
    if (!lt) {
        return -ENOENT;
    }

    TTP_RUN_SPIN_LOCKED({
        if ((lt->sock && lt->sock != tsk) || lt->sock_orphaned) {
            rc = -EBUSY;
        } else if (!lt->sock) {
            sock_hold(&tsk->sk);
            lt->sock = tsk;
            lt->sock_managed = true;
            lt->sock_orphaned = false;
        }
    });

    if (!rc) {
        unsigned long flags;

        spin_lock_irqsave(&tsk->lock, flags);
        tsk->kid = kid;
        spin_unlock_irqrestore(&tsk->lock, flags);
    }

    return rc;
}

static void ttp_sock_unbind_tag(struct ttp_sock *tsk)
{
    struct ttp_link_tag *lt;
    unsigned long flags;
    u64 kid;
    bool mapped = false;

    spin_lock_irqsave(&tsk->lock, flags);
    kid = tsk->kid;
    tsk->kid = 0;
    spin_unlock_irqrestore(&tsk->lock, flags);

    if (!kid) {
        return;
    }

    lt = ttp_rbtree_tag_get(kid);
    if (lt) {
        TTP_RUN_SPIN_LOCKED({
            if (lt->sock == tsk) {
                lt->sock = NULL;
                mapped = true;
            }
        });
    }

    if (mapped) {
        sock_put(&tsk->sk);
    }
}

static void ttp_sock_disconnect(struct ttp_sock *tsk)
{
    unsigned long flags;
    u64 kid;
    int state;
    struct ttp_link_tag *lt;
    bool defer_reset = false;

    spin_lock_irqsave(&tsk->lock, flags);
    kid = tsk->kid;
    state = tsk->state;
    spin_unlock_irqrestore(&tsk->lock, flags);

    if (kid) {
        lt = ttp_rbtree_tag_get(kid);
        if (lt && state == TTP_SS_ESTABLISHED && ttp_tag_has_pending_noc(lt)) {
            ttp_tag_mark_orphaned(lt);
            defer_reset = true;
        }

        ttp_sock_unbind_tag(tsk);
        if (lt) {
            if (defer_reset) {
                ttp_noc_requ(lt);
                ttp_tag_maybe_cleanup_orphan(lt);
            } else {
                ttp_tag_force_reset(lt);
            }
        }
    }
    skb_queue_purge(&tsk->rxq);

    spin_lock_irqsave(&tsk->lock, flags);
    memset(&tsk->target, 0, sizeof(tsk->target));
    memset(tsk->peer_node, 0, sizeof(tsk->peer_node));
    tsk->last_error = 0;
    tsk->state = tsk->ifindex ? TTP_SS_BOUND : TTP_SS_INIT;
    tsk->sk.sk_err = 0;
    spin_unlock_irqrestore(&tsk->lock, flags);

    wake_up_interruptible(&tsk->waitq);
    if (sk_sleep(&tsk->sk)) {
        wake_up_interruptible_all(sk_sleep(&tsk->sk));
    }
}

static int ttp_sock_build_target(struct ttp_sock *tsk, struct ttpoe_host_info *tg)
{
    unsigned long flags;

    spin_lock_irqsave(&tsk->lock, flags);
    if (!tsk->ifindex || !TTP_VC_ID__IS_VALID(tsk->vci)) {
        spin_unlock_irqrestore(&tsk->lock, flags);
        return -EINVAL;
    }

    memset(tg, 0, sizeof(*tg));
    ttp_prepare_mac_with_oui(tg->mac, TESLA_MAC_OUI, tsk->peer_node);
    tg->vc = tsk->vci;
    tg->gw = 0;
    tg->ip = 0;
    tg->ve = 1;
    spin_unlock_irqrestore(&tsk->lock, flags);

    return 0;
}

static int ttp_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    struct ttp_sock *tsk;

    if (!sk) {
        return 0;
    }

    tsk = ttp_sk(sk);
    ttp_sock_disconnect(tsk);
    ttp_sock_set_state(tsk, TTP_SS_CLOSED);
    sock_orphan(sk);
    sock->sk = NULL;
    sock_put(sk);
    return 0;
}

static int ttp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sockaddr_ttp *addr = (struct sockaddr_ttp *)uaddr;
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    struct net_device *dev;
    unsigned long flags;

    if (addr_len < sizeof(*addr) || !addr) {
        return -EINVAL;
    }
    if (addr->st_family != ttp_socket_family) {
        return -EINVAL;
    }
    if (addr->st_ifindex == 0 || !TTP_VC_ID__IS_VALID(addr->st_vci)) {
        return -EINVAL;
    }
    if (addr->st_node[0] || addr->st_node[1] || addr->st_node[2]) {
        return -EINVAL;
    }
    if (!ttp_etype_dev.dev || addr->st_ifindex != ttp_etype_dev.dev->ifindex) {
        return -ENODEV;
    }

    dev = dev_get_by_index(&init_net, addr->st_ifindex);
    if (!dev) {
        return -ENODEV;
    }
    dev_put(dev);

    spin_lock_irqsave(&tsk->lock, flags);
    if (tsk->state == TTP_SS_CONNECTING || tsk->state == TTP_SS_ESTABLISHED) {
        spin_unlock_irqrestore(&tsk->lock, flags);
        return -EBUSY;
    }
    spin_unlock_irqrestore(&tsk->lock, flags);

    ttp_sock_disconnect(tsk);

    spin_lock_irqsave(&tsk->lock, flags);
    memset(&tsk->target, 0, sizeof(tsk->target));
    memset(tsk->peer_node, 0, sizeof(tsk->peer_node));
    memcpy(tsk->local_node, ttp_etype_dev.dev->dev_addr + 3, sizeof(tsk->local_node));
    tsk->ifindex = addr->st_ifindex;
    tsk->vci = addr->st_vci;
    tsk->last_error = 0;
    tsk->state = TTP_SS_BOUND;
    spin_unlock_irqrestore(&tsk->lock, flags);

    return 0;
}

static int ttp_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags)
{
    struct sockaddr_ttp *addr = (struct sockaddr_ttp *)uaddr;
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    struct ttpoe_host_info target;
    struct ttp_link_tag *lt;
    long timeout;
    int rc;
    u64 kid;
    unsigned long irqflags;

    (void)flags;

    if (addr_len < sizeof(*addr) || !addr) {
        return -EINVAL;
    }
    if (addr->st_family != ttp_socket_family) {
        return -EINVAL;
    }
    if (!addr->st_node[0] && !addr->st_node[1] && !addr->st_node[2]) {
        return -EINVAL;
    }

    spin_lock_irqsave(&tsk->lock, irqflags);
    if (tsk->state != TTP_SS_BOUND && tsk->state != TTP_SS_ERROR &&
        tsk->state != TTP_SS_CLOSED) {
        spin_unlock_irqrestore(&tsk->lock, irqflags);
        return -EINVAL;
    }
    memcpy(tsk->peer_node, addr->st_node, sizeof(tsk->peer_node));
    tsk->last_error = 0;
    spin_unlock_irqrestore(&tsk->lock, irqflags);

    rc = ttp_sock_build_target(tsk, &target);
    if (rc) {
        return rc;
    }

    rc = ttpoe_host_resolve_target(&kid, &target);
    if (rc) {
        return rc;
    }

    rc = ttp_sock_bind_tag(tsk, kid);
    if (rc) {
        return rc;
    }

    spin_lock_irqsave(&tsk->lock, irqflags);
    tsk->target = target;
    tsk->state = TTP_SS_CONNECTING;
    spin_unlock_irqrestore(&tsk->lock, irqflags);

    rc = ttpoe_submit_event(NULL, NULL, 0, TTP_EV__TXQ__TTP_OPEN, &target);
    if (rc < 0) {
        ttp_sock_unbind_tag(tsk);
        lt = ttp_rbtree_tag_get(kid);
        if (lt) {
            ttp_tag_force_reset(lt);
        }
        ttp_sock_set_error(tsk, -rc);
        return rc;
    }

    timeout = wait_event_interruptible_timeout(
        tsk->waitq,
        READ_ONCE(tsk->state) != TTP_SS_CONNECTING,
        msecs_to_jiffies(TTP_CONNECT_TIMEOUT_MS));
    if (timeout < 0) {
        ttp_sock_unbind_tag(tsk);
        lt = ttp_rbtree_tag_get(kid);
        if (lt) {
            ttp_tag_force_reset(lt);
        }
        ttp_sock_set_state(tsk, TTP_SS_BOUND);
        return -ERESTARTSYS;
    }
    if (!timeout) {
        ttp_sock_unbind_tag(tsk);
        lt = ttp_rbtree_tag_get(kid);
        if (lt) {
            ttp_tag_force_reset(lt);
        }
        ttp_sock_set_error(tsk, ETIMEDOUT);
        return -ETIMEDOUT;
    }
    if (READ_ONCE(tsk->state) == TTP_SS_ERROR) {
        int err = READ_ONCE(tsk->last_error);
        ttp_sock_unbind_tag(tsk);
        lt = ttp_rbtree_tag_get(kid);
        if (lt) {
            ttp_tag_force_reset(lt);
        }
        return err ? -err : -ECONNREFUSED;
    }

    return 0;
}

static int ttp_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
    struct sockaddr_ttp *addr = (struct sockaddr_ttp *)uaddr;
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    unsigned long flags;

    memset(addr, 0, sizeof(*addr));
    spin_lock_irqsave(&tsk->lock, flags);
    addr->st_family = ttp_socket_family;
    addr->st_ifindex = tsk->ifindex;
    addr->st_vci = tsk->vci;
    memcpy(addr->st_node, peer ? tsk->peer_node : tsk->local_node, sizeof(addr->st_node));
    spin_unlock_irqrestore(&tsk->lock, flags);

    return sizeof(*addr);
}

static __poll_t ttp_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait)
{
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    __poll_t mask = 0;
    int state = READ_ONCE(tsk->state);

    poll_wait(file, sk_sleep(sock->sk), wait);

    if (!skb_queue_empty(&tsk->rxq)) {
        mask |= EPOLLIN | EPOLLRDNORM;
    }
    if (state == TTP_SS_ESTABLISHED) {
        mask |= EPOLLOUT | EPOLLWRNORM;
    }
    if (state == TTP_SS_ERROR || READ_ONCE(sock->sk->sk_err)) {
        mask |= EPOLLERR;
    }
    if (state == TTP_SS_CLOSED || state == TTP_SS_ERROR) {
        mask |= EPOLLHUP;
    }

    return mask;
}

static int ttp_sendmsg(struct socket *sock, struct msghdr *msg, size_t total_len)
{
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    struct sk_buff *skb;
    struct ttp_frame_hdr frh;
    u8 *buf;
    int rv;

    if (READ_ONCE(tsk->state) != TTP_SS_ESTABLISHED) {
        return -ENOTCONN;
    }
    if (!total_len || total_len > TTP_NOC_DAT_SIZE) {
        return -EMSGSIZE;
    }

    buf = ttp_skb_aloc(&skb, (int)total_len);
    if (!buf) {
        return -ENOMEM;
    }

    ttp_skb_pars(skb, &frh, NULL);
    if (memcpy_from_msg(frh.noc, msg, total_len)) {
        ttp_skb_drop(skb);
        return -EFAULT;
    }

    rv = ttpoe_submit_event(buf, skb, (int)total_len, TTP_EV__TXQ__TTP_PAYLOAD, &tsk->target);
    if (rv < 0) {
        ttp_skb_drop(skb);
        return rv;
    }

    return (int)total_len;
}

static int ttp_recvmsg(struct socket *sock, struct msghdr *msg, size_t total_len, int flags)
{
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    struct sk_buff *skb;
    int copied;
    int msg_len;
    int rc;

    if (flags & MSG_OOB) {
        return -EOPNOTSUPP;
    }

    if (flags & MSG_DONTWAIT) {
        skb = skb_dequeue(&tsk->rxq);
        if (!skb) {
            if (READ_ONCE(tsk->state) == TTP_SS_ERROR) {
                return -READ_ONCE(tsk->last_error);
            }
            if (READ_ONCE(tsk->state) == TTP_SS_CLOSED) {
                return 0;
            }
            return -EAGAIN;
        }
    } else {
        rc = wait_event_interruptible(
            tsk->waitq,
            !skb_queue_empty(&tsk->rxq) ||
            READ_ONCE(tsk->state) == TTP_SS_ERROR ||
            READ_ONCE(tsk->state) == TTP_SS_CLOSED);
        if (rc < 0) {
            return -ERESTARTSYS;
        }

        skb = skb_dequeue(&tsk->rxq);
        if (!skb) {
            if (READ_ONCE(tsk->state) == TTP_SS_ERROR) {
                return -READ_ONCE(tsk->last_error);
            }
            if (READ_ONCE(tsk->state) == TTP_SS_CLOSED) {
                return 0;
            }
            return -EAGAIN;
        }
    }

    msg_len = skb->len;
    copied = min_t(int, skb->len, total_len);
    if (memcpy_to_msg(msg, skb->data, copied)) {
        kfree_skb(skb);
        return -EFAULT;
    }
    if (copied < skb->len) {
        msg->msg_flags |= MSG_TRUNC;
    }
    kfree_skb(skb);
    return msg_len;
}

static void ttp_sock_destruct(struct sock *sk)
{
    struct ttp_sock *tsk = ttp_sk(sk);

    skb_queue_purge(&tsk->rxq);
}

struct proto ttp_proto = {
    .name = "TTP",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct ttp_sock),
};

struct proto_ops ttp_proto_ops = {
    .family = AF_TTP,
    .owner = THIS_MODULE,
    .release = ttp_release,
    .bind = ttp_bind,
    .connect = ttp_connect,
    .socketpair = ttp_socketpair,
    .accept = ttp_accept,
    .getname = ttp_getname,
    .poll = ttp_poll,
    .ioctl = ttp_ioctl,
    .listen = ttp_listen,
    .shutdown = ttp_sock_shutdown,
    .sendmsg = ttp_sendmsg,
    .recvmsg = ttp_recvmsg,
    .mmap = ttp_mmap,
};

int ttp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    struct ttp_sock *tsk;

    if (sock->type != SOCK_SEQPACKET) {
        return -ESOCKTNOSUPPORT;
    }
    if (protocol != 0) {
        return -EPROTONOSUPPORT;
    }

    sk = sk_alloc(net, ttp_socket_family, GFP_KERNEL, &ttp_proto, kern);
    if (!sk) {
        return -ENOMEM;
    }

    sock_init_data(sock, sk);
    sock->ops = &ttp_proto_ops;
    sk->sk_family = ttp_socket_family;
    sk->sk_protocol = protocol;
    sk->sk_destruct = ttp_sock_destruct;

    tsk = ttp_sk(sk);
    memset(&tsk->target, 0, sizeof(tsk->target));
    memset(tsk->local_node, 0, sizeof(tsk->local_node));
    memset(tsk->peer_node, 0, sizeof(tsk->peer_node));
    tsk->ifindex = 0;
    tsk->vci = 0;
    tsk->kid = 0;
    tsk->state = TTP_SS_INIT;
    tsk->last_error = 0;
    spin_lock_init(&tsk->lock);
    init_waitqueue_head(&tsk->waitq);
    skb_queue_head_init(&tsk->rxq);

    return 0;
}

int ttpoe_socket_payload_rx(u64 kid, const u8 *data, u16 nl)
{
    struct ttp_sock *tsk;
    struct sk_buff *skb;

    tsk = ttp_sock_lookup_kid(kid);
    if (!tsk) {
        return -ENOTCONN;
    }

    if (skb_queue_len(&tsk->rxq) >= TTP_SOCK_RXQ_LIMIT) {
        ttp_sock_put(tsk);
        return -ENOBUFS;
    }

    skb = alloc_skb(nl, GFP_ATOMIC);
    if (!skb) {
        ttp_sock_put(tsk);
        return -ENOMEM;
    }

    skb_put_data(skb, data, nl);
    skb_queue_tail(&tsk->rxq, skb);
    wake_up_interruptible(&tsk->waitq);
    if (sk_sleep(&tsk->sk)) {
        wake_up_interruptible_all(sk_sleep(&tsk->sk));
    }
    ttp_sock_put(tsk);
    return 0;
}

void ttpoe_socket_fsm_event(struct ttp_fsm_event *ev, int rs, int ns)
{
    struct ttp_sock *tsk;

    if (!ev || !ev->kid) {
        return;
    }

    tsk = ttp_sock_lookup_kid(ev->kid);
    if (!tsk) {
        return;
    }

    switch (ev->evt) {
    case TTP_EV__RXQ__TTP_OPEN_ACK:
        ttp_sock_set_state(tsk, TTP_SS_ESTABLISHED);
        break;
    case TTP_EV__RXQ__TTP_OPEN_NACK:
        ttp_sock_set_error(tsk, ECONNREFUSED);
        ttp_sock_unbind_tag(tsk);
        break;
    case TTP_EV__RXQ__TTP_NACK:
    case TTP_EV__RXQ__TTP_NACK_FULL:
    case TTP_EV__RXQ__TTP_NACK_NOLINK:
        if (READ_ONCE(tsk->state) == TTP_SS_CONNECTING) {
            ttp_sock_set_error(tsk, ECONNREFUSED);
            ttp_sock_unbind_tag(tsk);
        }
        break;
    default:
        break;
    }

    if (ns == TTP_ST__CLOSED && READ_ONCE(tsk->state) == TTP_SS_ESTABLISHED) {
        ttp_sock_set_error(tsk, EPIPE);
        ttp_sock_unbind_tag(tsk);
    }
    if (rs == TTP_RS__NOC_FAIL && READ_ONCE(tsk->state) == TTP_SS_CONNECTING) {
        ttp_sock_set_error(tsk, ETIMEDOUT);
        ttp_sock_unbind_tag(tsk);
    }

    wake_up_interruptible(&tsk->waitq);
    if (sk_sleep(&tsk->sk)) {
        wake_up_interruptible_all(sk_sleep(&tsk->sk));
    }
    ttp_sock_put(tsk);
}
