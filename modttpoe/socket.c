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
#define TTP_SOCK_MAX_FRAGS      DIV_ROUND_UP(TTP_SOCK_MSG_MAX, TTP_SOCK_FRAG_DATA_MAX)
#define TTP_SOCK_FRAG_MAGIC0    0x54
#define TTP_SOCK_FRAG_MAGIC1    0x46
#define TTP_SOCK_FRAG_MAGIC2    0x31

static LIST_HEAD(ttp_listener_head);
static DEFINE_SPINLOCK(ttp_listener_lock);

static int ttp_sock_bind_tag(struct ttp_sock *tsk, u64 kid);
static void ttp_sock_unbind_tag(struct ttp_sock *tsk);
static void ttp_sock_set_state(struct ttp_sock *tsk, int state);
static void ttp_sock_set_error(struct ttp_sock *tsk, int err);
static void ttp_sock_destruct(struct sock *sk);
static void ttp_sock_init_common(struct ttp_sock *tsk);
static void ttp_sock_wake(struct ttp_sock *tsk);
static int ttp_sock_request_close(struct ttp_sock *tsk);
static void ttp_sock_disconnect(struct ttp_sock *tsk);
static int ttp_sock_build_target(struct ttp_sock *tsk, struct ttpoe_host_info *tg);
static void ttp_sock_put(struct ttp_sock *tsk);

static void ttp_sock_wake(struct ttp_sock *tsk)
{
    wake_up_interruptible(&tsk->waitq);
    if (sk_sleep(&tsk->sk)) {
        wake_up_interruptible_all(sk_sleep(&tsk->sk));
    }
}

static void ttp_sock_init_common(struct ttp_sock *tsk)
{
    memset(&tsk->target, 0, sizeof(tsk->target));
    memset(tsk->local_node, 0, sizeof(tsk->local_node));
    memset(tsk->peer_node, 0, sizeof(tsk->peer_node));
    tsk->ifindex = 0;
    tsk->vci = 0;
    tsk->kid = 0;
    tsk->state = TTP_SS_INIT;
    tsk->last_error = 0;
    tsk->shutdown_mask = 0;
    tsk->close_sent = false;
    spin_lock_init(&tsk->lock);
    init_waitqueue_head(&tsk->waitq);
    skb_queue_head_init(&tsk->rxq);
    INIT_LIST_HEAD(&tsk->listener_link);
    INIT_LIST_HEAD(&tsk->acceptq);
    INIT_LIST_HEAD(&tsk->accept_link);
    tsk->listener = NULL;
    tsk->backlog = 0;
    tsk->accept_len = 0;
    tsk->reasm_skb = NULL;
    tsk->reasm_total_len = 0;
    tsk->reasm_next_off = 0;
}

static struct ttp_sock *ttp_listener_lookup(int ifindex, u8 vci)
{
    struct ttp_sock *tsk;

    list_for_each_entry(tsk, &ttp_listener_head, listener_link) {
        if (READ_ONCE(tsk->state) == TTP_SS_LISTEN &&
            tsk->ifindex == ifindex && tsk->vci == vci) {
            return tsk;
        }
    }

    return NULL;
}

static int ttp_listener_register(struct ttp_sock *tsk, int backlog)
{
    unsigned long flags;
    int rc = 0;

    spin_lock_irqsave(&ttp_listener_lock, flags);
    if (ttp_listener_lookup(tsk->ifindex, tsk->vci)) {
        rc = -EADDRINUSE;
    } else {
        list_add_tail(&tsk->listener_link, &ttp_listener_head);
        tsk->backlog = (u16)max(backlog, 1);
    }
    spin_unlock_irqrestore(&ttp_listener_lock, flags);

    return rc;
}

static void ttp_listener_unregister(struct ttp_sock *tsk)
{
    unsigned long flags;

    spin_lock_irqsave(&ttp_listener_lock, flags);
    if (!list_empty(&tsk->listener_link)) {
        list_del_init(&tsk->listener_link);
    }
    spin_unlock_irqrestore(&ttp_listener_lock, flags);
    tsk->backlog = 0;
}

static struct ttp_sock *ttp_sock_alloc_child(struct ttp_sock *listener)
{
    struct sock *sk;
    struct ttp_sock *child;

    sk = sk_alloc(sock_net(&listener->sk), ttp_socket_family, GFP_ATOMIC, &ttp_proto, 0);
    if (!sk) {
        return NULL;
    }

    sk->sk_family = ttp_socket_family;
    sk->sk_protocol = 0;
    sk->sk_destruct = ttp_sock_destruct;
    child = ttp_sk(sk);
    ttp_sock_init_common(child);
    child->listener = listener;
    child->ifindex = listener->ifindex;
    child->vci = listener->vci;
    memcpy(child->local_node, listener->local_node, sizeof(child->local_node));
    child->state = TTP_SS_ESTABLISHED;
    return child;
}

static void ttp_listener_cleanup_acceptq(struct ttp_sock *listener)
{
    struct ttp_sock *child, *tmp;
    LIST_HEAD(stale);
    unsigned long flags;

    spin_lock_irqsave(&listener->lock, flags);
    list_for_each_entry_safe(child, tmp, &listener->acceptq, accept_link) {
        list_del_init(&child->accept_link);
        child->listener = NULL;
        if (listener->accept_len) {
            listener->accept_len--;
        }
        list_add_tail(&child->accept_link, &stale);
    }
    spin_unlock_irqrestore(&listener->lock, flags);

    list_for_each_entry_safe(child, tmp, &stale, accept_link) {
        list_del_init(&child->accept_link);
        ttp_sock_disconnect(child);
        ttp_sock_set_state(child, TTP_SS_CLOSED);
        sock_orphan(&child->sk);
        sock_put(&child->sk);
    }
}

static int ttp_listener_enqueue_child(struct ttp_sock *listener, struct ttp_sock *child)
{
    unsigned long flags;
    int rc = 0;

    spin_lock_irqsave(&listener->lock, flags);
    if (listener->state != TTP_SS_LISTEN ||
        (listener->backlog && listener->accept_len >= listener->backlog)) {
        rc = -ENOBUFS;
    } else {
        list_add_tail(&child->accept_link, &listener->acceptq);
        listener->accept_len++;
    }
    spin_unlock_irqrestore(&listener->lock, flags);

    if (!rc) {
        ttp_sock_wake(listener);
    }
    return rc;
}

static struct ttp_sock *ttp_listener_dequeue_child(struct ttp_sock *listener)
{
    struct ttp_sock *child = NULL;
    unsigned long flags;

    spin_lock_irqsave(&listener->lock, flags);
    child = list_first_entry_or_null(&listener->acceptq, struct ttp_sock, accept_link);
    if (child) {
        list_del_init(&child->accept_link);
        if (listener->accept_len) {
            listener->accept_len--;
        }
        child->listener = NULL;
    }
    spin_unlock_irqrestore(&listener->lock, flags);

    return child;
}

int ttpoe_socket_accept_prepare(u64 kid)
{
    struct ttp_link_tag *lt;
    struct ttp_sock *listener = NULL;
    struct ttp_sock *child = NULL;
    struct ttpoe_host_info target;
    unsigned long flags;
    int rc = 0;

    if (!kid || !ttp_etype_dev.dev) {
        return 0;
    }

    lt = ttp_rbtree_tag_get(kid);
    if (!lt) {
        return -ENOENT;
    }

    spin_lock_irqsave(&ttp_listener_lock, flags);
    listener = ttp_listener_lookup(ttp_etype_dev.dev->ifindex, lt->vci);
    if (listener) {
        sock_hold(&listener->sk);
    }
    spin_unlock_irqrestore(&ttp_listener_lock, flags);

    if (!listener) {
        return 0;
    }

    child = ttp_sock_alloc_child(listener);
    if (!child) {
        rc = -ENOMEM;
        goto out_put_listener;
    }

    memcpy(child->peer_node, lt->mac, sizeof(child->peer_node));
    rc = ttp_sock_build_target(child, &target);
    if (rc) {
        goto out_drop_child;
    }
    child->target = target;

    rc = ttp_sock_bind_tag(child, kid);
    if (rc) {
        goto out_drop_child;
    }

    rc = ttp_listener_enqueue_child(listener, child);
    if (rc) {
        ttp_sock_unbind_tag(child);
        goto out_drop_child;
    }

    ttp_sock_put(listener);
    return 0;

out_drop_child:
    ttp_sock_disconnect(child);
    ttp_sock_set_state(child, TTP_SS_CLOSED);
    sock_orphan(&child->sk);
    sock_put(&child->sk);
out_put_listener:
    ttp_sock_put(listener);
    return rc;
}

static bool ttp_sock_frag_noc_is_socket(const struct ttp_ttpoe_noc_hdr *nh)
{
    return nh->xhdr1_fmt.type == TTP_ET__PAYLOAD_OFFSET &&
           nh->xhdr1_fmt.extn_hdr1[1] == TTP_SOCK_FRAG_META_VER &&
           nh->xhdr1_fmt.extn_hdr1[4] == TTP_SOCK_FRAG_MAGIC0 &&
           nh->xhdr1_fmt.extn_hdr1[5] == TTP_SOCK_FRAG_MAGIC1 &&
           nh->xhdr1_fmt.extn_hdr1[6] == TTP_SOCK_FRAG_MAGIC2;
}

static u16 ttp_sock_frag_noc_len(const struct ttp_ttpoe_noc_hdr *nh)
{
    return ((u16)nh->xhdr1_fmt.extn_hdr1[2] << 8) |
           (u16)nh->xhdr1_fmt.extn_hdr1[3];
}

static void ttp_sock_frag_noc_set_len(struct ttp_ttpoe_noc_hdr *nh, u16 frag_len)
{
    nh->xhdr1_fmt.extn_hdr1[2] = (u8)(frag_len >> 8);
    nh->xhdr1_fmt.extn_hdr1[3] = (u8)(frag_len & 0xff);
}

static void ttp_sock_frag_noc_pack(struct ttp_ttpoe_noc_hdr *nh, u8 flags,
                                   u32 total_len, u32 frag_off, u16 frag_len)
{
    memset(nh, 0, sizeof(*nh));
    nh->xhdr1_fmt.type = TTP_ET__PAYLOAD_OFFSET;
    nh->xhdr1_fmt.extn_hdr1[0] = flags;
    nh->xhdr1_fmt.extn_hdr1[1] = TTP_SOCK_FRAG_META_VER;
    ttp_sock_frag_noc_set_len(nh, frag_len);
    nh->xhdr1_fmt.extn_hdr1[4] = TTP_SOCK_FRAG_MAGIC0;
    nh->xhdr1_fmt.extn_hdr1[5] = TTP_SOCK_FRAG_MAGIC1;
    nh->xhdr1_fmt.extn_hdr1[6] = TTP_SOCK_FRAG_MAGIC2;
    nh->xhdr2_u64 = cpu_to_be64(((u64)total_len << 32) | frag_off);
}

static void ttp_sock_reasm_reset(struct ttp_sock *tsk)
{
    struct sk_buff *skb = NULL;
    unsigned long flags;

    spin_lock_irqsave(&tsk->lock, flags);
    skb = tsk->reasm_skb;
    tsk->reasm_skb = NULL;
    tsk->reasm_total_len = 0;
    tsk->reasm_next_off = 0;
    spin_unlock_irqrestore(&tsk->lock, flags);

    if (skb) {
        kfree_skb(skb);
    }
}

static int ttp_sock_queue_complete(struct ttp_sock *tsk, struct sk_buff *skb)
{
    if (skb_queue_len(&tsk->rxq) >= TTP_SOCK_RXQ_LIMIT) {
        kfree_skb(skb);
        return -ENOBUFS;
    }

    skb_queue_tail(&tsk->rxq, skb);
    wake_up_interruptible(&tsk->waitq);
    if (sk_sleep(&tsk->sk)) {
        wake_up_interruptible_all(sk_sleep(&tsk->sk));
    }
    return 0;
}

static bool ttp_sock_is_fragmented_payload(const u8 *data, u16 nl)
{
    const struct ttp_ttpoe_noc_hdr *nh;

    if (!data || nl < sizeof(*nh)) {
        return false;
    }

    nh = (const struct ttp_ttpoe_noc_hdr *)data;
    return ttp_sock_frag_noc_is_socket(nh);
}

static int ttp_sock_payload_rx_fragment(struct ttp_sock *tsk, const u8 *data, u16 nl)
{
    const struct ttp_ttpoe_noc_hdr *nh;
    const u8 *payload;
    struct sk_buff *skb = NULL;
    unsigned long flags;
    u16 frag_len;
    u32 total_len, frag_off;
    u64 xhdr2;
    bool first, last, complete = false;
    int rc = 0;

    if (nl < sizeof(*nh)) {
        return -EPROTO;
    }

    nh = (const struct ttp_ttpoe_noc_hdr *)data;
    if (!ttp_sock_frag_noc_is_socket(nh)) {
        return -EPROTO;
    }

    frag_len = ttp_sock_frag_noc_len(nh);
    xhdr2 = be64_to_cpu(nh->xhdr2_u64);
    total_len = (u32)(xhdr2 >> 32);
    frag_off = (u32)xhdr2;
    first = !!(nh->xhdr1_fmt.extn_hdr1[0] & TTP_SOCK_FRAG_F_FIRST);
    last = !!(nh->xhdr1_fmt.extn_hdr1[0] & TTP_SOCK_FRAG_F_LAST);
    payload = data + sizeof(*nh);

    if (!frag_len || total_len > TTP_SOCK_MSG_MAX ||
        frag_len != (u16)(nl - sizeof(*nh))) {
        ttp_sock_reasm_reset(tsk);
        return -EPROTO;
    }
    if (frag_off + frag_len > total_len) {
        ttp_sock_reasm_reset(tsk);
        return -EPROTO;
    }

    if (first) {
        if (frag_off != 0) {
            ttp_sock_reasm_reset(tsk);
            return -EPROTO;
        }
        ttp_sock_reasm_reset(tsk);
        skb = alloc_skb(total_len, GFP_KERNEL);
        if (!skb) {
            return -ENOMEM;
        }

        spin_lock_irqsave(&tsk->lock, flags);
        tsk->reasm_skb = skb;
        tsk->reasm_total_len = total_len;
        tsk->reasm_next_off = 0;
        spin_unlock_irqrestore(&tsk->lock, flags);
    }

    spin_lock_irqsave(&tsk->lock, flags);
    skb = tsk->reasm_skb;
    if (!skb || !tsk->reasm_total_len) {
        rc = -EPROTO;
        goto out_unlock;
    }
    if (tsk->reasm_total_len != total_len || tsk->reasm_next_off != frag_off || skb->len != frag_off) {
        rc = -EPROTO;
        goto out_unlock;
    }

    skb_put_data(skb, payload, frag_len);
    tsk->reasm_next_off += frag_len;
    complete = last && tsk->reasm_next_off == tsk->reasm_total_len;
    if (complete) {
        tsk->reasm_skb = NULL;
        tsk->reasm_total_len = 0;
        tsk->reasm_next_off = 0;
    }
out_unlock:
    spin_unlock_irqrestore(&tsk->lock, flags);

    if (rc < 0) {
        ttp_sock_reasm_reset(tsk);
        return rc;
    }

    if (!complete) {
        return 0;
    }

    return ttp_sock_queue_complete(tsk, skb);
}

static int ttp_listen(struct socket *sock, int backlog)
{
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    int rc;

    if (tsk->state != TTP_SS_BOUND) {
        return -EINVAL;
    }

    rc = ttp_listener_register(tsk, backlog);
    if (rc) {
        return rc;
    }

    ttp_sock_set_state(tsk, TTP_SS_LISTEN);
    return 0;
}

static int ttp_sock_shutdown(struct socket *sock, int flags)
{
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    unsigned long irqflags;
    int how = flags & SHUTDOWN_MASK;
    bool wake = false;
    int rc = 0;

    if (how < SHUT_RD || how > SHUT_RDWR) {
        return -EINVAL;
    }
    if (tsk->state == TTP_SS_INIT || tsk->state == TTP_SS_BOUND || tsk->state == TTP_SS_LISTEN) {
        return -ENOTCONN;
    }

    spin_lock_irqsave(&tsk->lock, irqflags);
    if (how == SHUT_RD || how == SHUT_RDWR) {
        tsk->shutdown_mask |= TTP_SOCK_SHUT_RD;
        wake = true;
    }
    if (how == SHUT_WR || how == SHUT_RDWR) {
        tsk->shutdown_mask |= TTP_SOCK_SHUT_WR;
        if (tsk->state == TTP_SS_ESTABLISHED) {
            tsk->state = TTP_SS_LOCAL_CLOSED;
        } else if (tsk->state == TTP_SS_PEER_CLOSED) {
            tsk->state = TTP_SS_CLOSED;
        }
        wake = true;
    }
    spin_unlock_irqrestore(&tsk->lock, irqflags);

    if (how == SHUT_RD || how == SHUT_RDWR) {
        skb_queue_purge(&tsk->rxq);
        ttp_sock_reasm_reset(tsk);
    }

    if (how == SHUT_WR || how == SHUT_RDWR) {
        rc = ttp_sock_request_close(tsk);
        if (rc && rc != -EALREADY && rc != -ENOTCONN && rc != -EAGAIN) {
            return rc;
        }
    }

    if (wake) {
        ttp_sock_wake(tsk);
    }

    return 0;
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
    struct ttp_sock *listener = ttp_sk(sock->sk);
    struct ttp_sock *child;
    int rc;

    (void)kern;

    if (listener->state != TTP_SS_LISTEN) {
        return -EINVAL;
    }

    if (flags & O_NONBLOCK) {
        child = ttp_listener_dequeue_child(listener);
        if (!child) {
            return -EAGAIN;
        }
    } else {
        rc = wait_event_interruptible(
            listener->waitq,
            !list_empty(&listener->acceptq) ||
            READ_ONCE(listener->state) == TTP_SS_ERROR ||
            READ_ONCE(listener->state) == TTP_SS_CLOSED);
        if (rc < 0) {
            return -ERESTARTSYS;
        }
        child = ttp_listener_dequeue_child(listener);
        if (!child) {
            if (READ_ONCE(listener->state) == TTP_SS_ERROR) {
                return -READ_ONCE(listener->last_error);
            }
            return -EAGAIN;
        }
    }

    newsock->ops = &ttp_proto_ops;
    sock_graft(&child->sk, newsock);
    newsock->state = SS_CONNECTED;
    return 0;
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
    ttp_sock_reasm_reset(tsk);
    ttp_sock_unbind_tag(tsk);
    ttp_sock_put(tsk);
}

static void ttp_sock_set_state(struct ttp_sock *tsk, int state)
{
    unsigned long flags;

    spin_lock_irqsave(&tsk->lock, flags);
    tsk->state = state;
    spin_unlock_irqrestore(&tsk->lock, flags);
    ttp_sock_wake(tsk);
}

static void ttp_sock_set_error(struct ttp_sock *tsk, int err)
{
    unsigned long flags;

    spin_lock_irqsave(&tsk->lock, flags);
    tsk->last_error = err;
    tsk->state = TTP_SS_ERROR;
    tsk->sk.sk_err = err;
    spin_unlock_irqrestore(&tsk->lock, flags);
    ttp_sock_wake(tsk);
}

static int ttp_sock_request_close(struct ttp_sock *tsk)
{
    struct ttpoe_host_info target;
    struct ttp_link_tag *lt;
    unsigned long flags;
    int rc = 0;
    bool do_close = false;

    spin_lock_irqsave(&tsk->lock, flags);
    if (tsk->close_sent) {
        spin_unlock_irqrestore(&tsk->lock, flags);
        return -EALREADY;
    }
    if (!tsk->kid || (tsk->state != TTP_SS_ESTABLISHED &&
                      tsk->state != TTP_SS_LOCAL_CLOSED &&
                      tsk->state != TTP_SS_PEER_CLOSED)) {
        spin_unlock_irqrestore(&tsk->lock, flags);
        return -ENOTCONN;
    }
    target = tsk->target;
    tsk->close_sent = true;
    do_close = true;
    spin_unlock_irqrestore(&tsk->lock, flags);

    lt = ttp_rbtree_tag_get(tsk->kid);
    if (lt && ttp_tag_has_pending_noc(lt)) {
        spin_lock_irqsave(&tsk->lock, flags);
        tsk->close_sent = false;
        spin_unlock_irqrestore(&tsk->lock, flags);
        return -EAGAIN;
    }

    if (do_close) {
        rc = ttpoe_submit_event(NULL, NULL, 0, TTP_EV__TXQ__TTP_CLOSE, &target);
        if (rc < 0) {
            spin_lock_irqsave(&tsk->lock, flags);
            tsk->close_sent = false;
            spin_unlock_irqrestore(&tsk->lock, flags);
            return rc;
        }
    }

    return 0;
}

static void ttp_sock_note_peer_closed(struct ttp_sock *tsk)
{
    unsigned long flags;
    bool drop_reasm = false;

    spin_lock_irqsave(&tsk->lock, flags);
    if (tsk->state == TTP_SS_ESTABLISHED) {
        tsk->state = TTP_SS_PEER_CLOSED;
    } else if (tsk->state == TTP_SS_LOCAL_CLOSED) {
        tsk->state = TTP_SS_CLOSED;
    }
    drop_reasm = tsk->reasm_skb != NULL;
    spin_unlock_irqrestore(&tsk->lock, flags);

    if (drop_reasm) {
        ttp_sock_reasm_reset(tsk);
    }
    ttp_sock_wake(tsk);
}

static void ttp_sock_note_local_closed(struct ttp_sock *tsk)
{
    unsigned long flags;

    spin_lock_irqsave(&tsk->lock, flags);
    if (tsk->state == TTP_SS_ESTABLISHED) {
        tsk->state = TTP_SS_LOCAL_CLOSED;
    } else if (tsk->state == TTP_SS_PEER_CLOSED) {
        tsk->state = TTP_SS_CLOSED;
    }
    spin_unlock_irqrestore(&tsk->lock, flags);
    ttp_sock_wake(tsk);
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

    if (tsk->state == TTP_SS_LISTEN) {
        ttp_listener_unregister(tsk);
        ttp_listener_cleanup_acceptq(tsk);
    }

    if (kid) {
        lt = ttp_rbtree_tag_get(kid);
        if (lt &&
            (state == TTP_SS_ESTABLISHED ||
             state == TTP_SS_LOCAL_CLOSED ||
             state == TTP_SS_PEER_CLOSED) &&
            ttp_tag_has_pending_noc(lt)) {
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
    ttp_sock_reasm_reset(tsk);

    spin_lock_irqsave(&tsk->lock, flags);
    memset(&tsk->target, 0, sizeof(tsk->target));
    memset(tsk->peer_node, 0, sizeof(tsk->peer_node));
    tsk->last_error = 0;
    tsk->shutdown_mask = 0;
    tsk->close_sent = false;
    tsk->state = tsk->ifindex ? TTP_SS_BOUND : TTP_SS_INIT;
    tsk->sk.sk_err = 0;
    spin_unlock_irqrestore(&tsk->lock, flags);
    ttp_sock_wake(tsk);
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
    sock->state = SS_DISCONNECTING;
    if (tsk->state == TTP_SS_ESTABLISHED || tsk->state == TTP_SS_PEER_CLOSED) {
        int rc;

        tsk->shutdown_mask |= TTP_SOCK_SHUT_WR;
        ttp_sock_note_local_closed(tsk);
        rc = ttp_sock_request_close(tsk);
        if (rc && rc != -EALREADY && rc != -ENOTCONN && rc != -EAGAIN) {
            return rc;
        }
    }
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
    if (tsk->state == TTP_SS_CONNECTING || tsk->state == TTP_SS_ESTABLISHED ||
        tsk->state == TTP_SS_LISTEN) {
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
    tsk->shutdown_mask = 0;
    tsk->close_sent = false;
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
    sock->state = SS_CONNECTING;

    rc = ttpoe_submit_event(NULL, NULL, 0, TTP_EV__TXQ__TTP_OPEN, &target);
    if (rc < 0) {
        ttp_sock_unbind_tag(tsk);
        lt = ttp_rbtree_tag_get(kid);
        if (lt) {
            ttp_tag_force_reset(lt);
        }
        ttp_sock_set_error(tsk, -rc);
        sock->state = SS_UNCONNECTED;
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
        sock->state = SS_UNCONNECTED;
        return -ERESTARTSYS;
    }
    if (!timeout) {
        ttp_sock_unbind_tag(tsk);
        lt = ttp_rbtree_tag_get(kid);
        if (lt) {
            ttp_tag_force_reset(lt);
        }
        ttp_sock_set_error(tsk, ETIMEDOUT);
        sock->state = SS_UNCONNECTED;
        return -ETIMEDOUT;
    }
    if (READ_ONCE(tsk->state) == TTP_SS_ERROR) {
        int err = READ_ONCE(tsk->last_error);
        ttp_sock_unbind_tag(tsk);
        lt = ttp_rbtree_tag_get(kid);
        if (lt) {
            ttp_tag_force_reset(lt);
        }
        sock->state = SS_UNCONNECTED;
        return err ? -err : -ECONNREFUSED;
    }

    sock->state = SS_CONNECTED;
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

    if (state == TTP_SS_LISTEN) {
        if (!list_empty(&tsk->acceptq)) {
            mask |= EPOLLIN | EPOLLRDNORM;
        }
        if (READ_ONCE(tsk->state) == TTP_SS_ERROR) {
            mask |= EPOLLERR;
        }
        if (READ_ONCE(tsk->state) == TTP_SS_CLOSED) {
            mask |= EPOLLHUP;
        }
        return mask;
    }

    if (!skb_queue_empty(&tsk->rxq)) {
        mask |= EPOLLIN | EPOLLRDNORM;
    }
    if ((state == TTP_SS_ESTABLISHED || state == TTP_SS_PEER_CLOSED) &&
        !(READ_ONCE(tsk->shutdown_mask) & TTP_SOCK_SHUT_WR)) {
        mask |= EPOLLOUT | EPOLLWRNORM;
    }
    if (state == TTP_SS_ERROR || READ_ONCE(sock->sk->sk_err)) {
        mask |= EPOLLERR;
    }
    if (state == TTP_SS_PEER_CLOSED || state == TTP_SS_CLOSED || state == TTP_SS_ERROR) {
        mask |= EPOLLHUP;
    }

    return mask;
}

static int ttp_sendmsg(struct socket *sock, struct msghdr *msg, size_t total_len)
{
    struct ttp_sock *tsk = ttp_sk(sock->sk);
    struct ttp_fsm_event *evs[TTP_SOCK_MAX_FRAGS] = {0};
    struct sk_buff *skb;
    struct ttp_frame_hdr frh;
    u8 *buf;
    u64 kid;
    size_t remaining;
    size_t frag_off;
    size_t frag_len;
    u8 frag_flags;
    int frag_cnt = 0;
    int i;
    int rv;
    int state;

    state = READ_ONCE(tsk->state);
    if (state != TTP_SS_ESTABLISHED && state != TTP_SS_PEER_CLOSED) {
        if (state == TTP_SS_LOCAL_CLOSED || state == TTP_SS_CLOSED) {
            return -EPIPE;
        }
        return -ENOTCONN;
    }
    if (READ_ONCE(tsk->shutdown_mask) & TTP_SOCK_SHUT_WR) {
        return -EPIPE;
    }
    if (!total_len || total_len > TTP_SOCK_MSG_MAX) {
        return -EMSGSIZE;
    }
    kid = READ_ONCE(tsk->kid);
    if (!kid) {
        return -ENOTCONN;
    }

    if (total_len <= TTP_NOC_DAT_SIZE) {
        buf = ttp_skb_aloc(&skb, (int)total_len);
        if (!buf) {
            return -ENOMEM;
        }

        ttp_skb_pars(skb, &frh, NULL);
        frh.ttp->conn_extension = 0;
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

    remaining = total_len;
    frag_off = 0;
    while (remaining) {
        if (frag_cnt >= TTP_SOCK_MAX_FRAGS) {
            rv = -E2BIG;
            goto fail_fragments;
        }
        frag_len = min_t(size_t, remaining, TTP_SOCK_FRAG_DATA_MAX);

        buf = ttp_skb_aloc(&skb, sizeof(*frh.noc) + (int)frag_len);
        if (!buf) {
            rv = -ENOMEM;
            goto fail_fragments;
        }

        ttp_skb_pars(skb, &frh, NULL);
        frh.ttp->conn_extension = TTP_ET__PAYLOAD_OFFSET;
        frag_flags = 0;
        if (!frag_off) {
            frag_flags |= TTP_SOCK_FRAG_F_FIRST;
        }
        if (frag_off + frag_len == total_len) {
            frag_flags |= TTP_SOCK_FRAG_F_LAST;
        }
        ttp_sock_frag_noc_pack(frh.noc, frag_flags,
                               (u32)total_len, (u32)frag_off, (u16)frag_len);

        if (memcpy_from_msg((u8 *)frh.dat, msg, frag_len)) {
            ttp_skb_drop(skb);
            rv = -EFAULT;
            goto fail_fragments;
        }

        if (!ttp_evt_pget(&evs[frag_cnt])) {
            ttp_skb_drop(skb);
            rv = -ENOBUFS;
            goto fail_fragments;
        }

        evs[frag_cnt]->evt = TTP_EV__TXQ__TTP_PAYLOAD;
        evs[frag_cnt]->kid = kid;
        evs[frag_cnt]->mrk = TTP_EVENTS_FENCE__NOC_ELEM;
        evs[frag_cnt]->psi.noc_len = sizeof(*frh.noc) + frag_len;
        evs[frag_cnt]->tsk = skb;
        evs[frag_cnt]->psi.skb_dat = buf;
        evs[frag_cnt]->psi.skb_len = skb->len;
        frag_cnt++;

        frag_off += frag_len;
        remaining -= frag_len;
    }

    for (i = 0; i < frag_cnt; i++) {
        TTP_EVLOG(evs[i], TTP_LG__NOC_PAYLOAD_TX, TTP_OP__TTP_PAYLOAD);
        ttp_noc_enqu(evs[i]);
    }

    return (int)total_len;

fail_fragments:
    for (i = 0; i < frag_cnt; i++) {
        ttp_evt_pput(evs[i]);
    }
    return rv;
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
    if (READ_ONCE(tsk->state) == TTP_SS_LISTEN) {
        return -EOPNOTSUPP;
    }
    if (READ_ONCE(tsk->shutdown_mask) & TTP_SOCK_SHUT_RD) {
        return 0;
    }

    if (flags & MSG_DONTWAIT) {
        skb = skb_dequeue(&tsk->rxq);
        if (!skb) {
            if (READ_ONCE(tsk->state) == TTP_SS_ERROR) {
                return -READ_ONCE(tsk->last_error);
            }
            if (READ_ONCE(tsk->state) == TTP_SS_CLOSED ||
                READ_ONCE(tsk->state) == TTP_SS_PEER_CLOSED) {
                return 0;
            }
            return -EAGAIN;
        }
    } else {
        rc = wait_event_interruptible(
            tsk->waitq,
            !skb_queue_empty(&tsk->rxq) ||
            READ_ONCE(tsk->state) == TTP_SS_ERROR ||
            READ_ONCE(tsk->state) == TTP_SS_CLOSED ||
            READ_ONCE(tsk->state) == TTP_SS_PEER_CLOSED ||
            (READ_ONCE(tsk->shutdown_mask) & TTP_SOCK_SHUT_RD));
        if (rc < 0) {
            return -ERESTARTSYS;
        }

        skb = skb_dequeue(&tsk->rxq);
        if (!skb) {
            if (READ_ONCE(tsk->state) == TTP_SS_ERROR) {
                return -READ_ONCE(tsk->last_error);
            }
            if (READ_ONCE(tsk->state) == TTP_SS_CLOSED ||
                READ_ONCE(tsk->state) == TTP_SS_PEER_CLOSED ||
                (READ_ONCE(tsk->shutdown_mask) & TTP_SOCK_SHUT_RD)) {
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
    ttp_sock_reasm_reset(tsk);
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
    ttp_sock_init_common(tsk);

    return 0;
}

int ttpoe_socket_payload_rx(u64 kid, const u8 *data, u16 nl)
{
    struct ttp_sock *tsk;
    struct sk_buff *skb;
    int rc;

    tsk = ttp_sock_lookup_kid(kid);
    if (!tsk) {
        return -ENOTCONN;
    }

    if (ttp_sock_is_fragmented_payload(data, nl)) {
        rc = ttp_sock_payload_rx_fragment(tsk, data, nl);
        ttp_sock_put(tsk);
        return rc;
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
    rc = ttp_sock_queue_complete(tsk, skb);
    ttp_sock_put(tsk);
    return rc;
}

void ttpoe_socket_fsm_event(struct ttp_fsm_event *ev, int rs, int ns)
{
    struct ttp_sock *tsk;
    int state;

    if (!ev || !ev->kid) {
        return;
    }

    tsk = ttp_sock_lookup_kid(ev->kid);
    if (!tsk) {
        return;
    }

    state = READ_ONCE(tsk->state);

    switch (ev->evt) {
    case TTP_EV__RXQ__TTP_OPEN_ACK:
        if (state == TTP_SS_CONNECTING) {
            ttp_sock_set_state(tsk, TTP_SS_ESTABLISHED);
        }
        break;
    case TTP_EV__RXQ__TTP_OPEN_NACK:
        if (state == TTP_SS_CONNECTING) {
            ttp_sock_set_error(tsk, ECONNREFUSED);
            ttp_sock_unbind_tag(tsk);
        }
        break;
    case TTP_EV__RXQ__TTP_NACK:
        if (state == TTP_SS_CONNECTING) {
            ttp_sock_set_error(tsk, ECONNREFUSED);
            ttp_sock_unbind_tag(tsk);
        }
        break;
    case TTP_EV__RXQ__TTP_NACK_FULL:
        if (state == TTP_SS_CONNECTING) {
            ttp_sock_set_error(tsk, ECONNREFUSED);
            ttp_sock_unbind_tag(tsk);
        } else {
            ttp_sock_wake(tsk);
        }
        break;
    case TTP_EV__RXQ__TTP_NACK_NOLINK:
        if (state == TTP_SS_CONNECTING) {
            ttp_sock_set_error(tsk, ECONNREFUSED);
        } else {
            ttp_sock_set_error(tsk, EHOSTUNREACH);
        }
        ttp_sock_unbind_tag(tsk);
        break;
    case TTP_EV__RXQ__TTP_CLOSE:
        ttp_sock_note_peer_closed(tsk);
        break;
    case TTP_EV__RXQ__TTP_CLOSE_ACK:
        if (state == TTP_SS_LOCAL_CLOSED || state == TTP_SS_PEER_CLOSED) {
            ttp_sock_set_state(tsk, TTP_SS_CLOSED);
        }
        break;
    case TTP_EV__RXQ__TTP_CLOSE_NACK:
        ttp_sock_set_error(tsk, ECONNRESET);
        ttp_sock_unbind_tag(tsk);
        break;
    default:
        break;
    }

    if (rs == TTP_RS__NOC_FAIL) {
        if (state == TTP_SS_CONNECTING) {
            ttp_sock_set_error(tsk, ETIMEDOUT);
        } else if (state != TTP_SS_CLOSED && state != TTP_SS_ERROR) {
            ttp_sock_set_error(tsk, ETIMEDOUT);
        }
        ttp_sock_unbind_tag(tsk);
    }
    if (ns == TTP_ST__CLOSED &&
        READ_ONCE(tsk->state) != TTP_SS_CLOSED &&
        READ_ONCE(tsk->state) != TTP_SS_ERROR) {
        ttp_sock_note_peer_closed(tsk);
    }

    ttp_sock_wake(tsk);
    ttp_sock_put(tsk);
}
