// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Tesla Inc. All rights reserved.
 *
 * TTP (TTPoE) A reference implementation of Tesla Transport Protocol (TTP) that runs
 *             directly over Ethernet Layer-2 Network. This is implemented as a Loadable
 *             Kernel Module that establishes a TTP-peer connection with another instance
 *             of the same module running on another Linux machine on the same Layer-2
 *             network. Since TTP runs over Ethernet, it is often referred to as TTP Over
 *             Ethernet (TTPoE).
 *
 *             The Protocol is specified to work at high bandwidths over 100Gbps and is
 *             mainly designed to be implemented in Hardware as part of Tesla's DOJO
 *             project.
 *
 *             This public release of the TTP software implementation is aligned with the
 *             patent disclosure and public release of the main TTP Protocol
 *             specification. Users of this software module must take into consideration
 *             those disclosures in addition to the license agreement mentioned here.
 *
 * Authors:    Diwakar Tundlam <dntundlam@tesla.com>
 *             Bill Chang <wichang@tesla.com>
 *             Spencer Sharkey <spsharkey@tesla.com>
 *
 * TTP-Spec:   Eric Quinnell <equinnell@tesla.com>
 *             Doug Williams <dougwilliams@tesla.com>
 *             Christopher Hsiong <chsiong@tesla.com>
 *
 * Version:    08/26/2022 wichang@tesla.com, "Initial version"
 *             02/09/2023 spsharkey@tesla.com, "add ttpoe header parser + test"
 *             05/11/2023 dntundlam@tesla.com, "ttpoe layers - nwk, transport, payload"
 *             07/11/2023 dntundlam@tesla.com, "functional state-machine, added tests"
 *             09/29/2023 dntundlam@tesla.com, "final touches"
 *             09/10/2024 dntundlam@tesla.com, "sync with TTP_Opcodes.pdf [rev 1.5]"
 *
 * This software is licensed under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, and may be copied, distributed, and
 * modified under those terms.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; Without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 */

#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/etherdevice.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <linux/crc16.h>
#include <net/addrconf.h>
#include <net/ip.h>

#include <ttp.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "noc.h"
#include "socket.h"
#include "print.h"

/* 'on_enter' functions: */
/* CLOSED: Tag reset */
TTP_NOINLINE
static bool ttp_fsm_sef__TAG_RESET (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d\n", __FUNCTION__, cpu_to_be64 (ev->kid), ev->idx);

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    lt->state = TTP_ST__CLOSED;

    TTP_DBG ("`-> Link-DOWN: State %s\n", TTP_STATE_NAME (lt->state));
    TTP_EVLOG (ev, TTP_LG__TTP_LINK_DOWN, TTP_OP__invalid);

    ttp_tag_reset (lt);         /* clear link-tag */
    return true;
}


/* OPEN: Check NOC */
TTP_NOINLINE
static bool ttp_fsm_sef__CHECK_NOC (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d\n", __FUNCTION__, cpu_to_be64 (ev->kid), ev->idx);

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    lt->state = TTP_ST__OPEN;

    TTP_DBG ("`-> Link-UP: State %s\n", TTP_STATE_NAME (lt->state));
    TTP_EVLOG (ev, TTP_LG__TTP_LINK_UP, TTP_OP__invalid);

    ttp_noc_requ (lt);
    return true;
}

/* OPEN_SENT: Start timer */
TTP_NOINLINE
static bool ttp_fsm_sef__OPEN_TIMER (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx\n", __FUNCTION__, cpu_to_be64 (ev->kid));

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    lt->state = TTP_ST__OPEN_SENT;

    if (timer_pending (&lt->tmr)) {
        mod_timer_pending (&lt->tmr, jiffies + msecs_to_jiffies (TTP_TMX_OPEN_SENT));
        TTP_EVLOG (ev, TTP_LG__SH_TIMER_RESTART, TTP_OP__invalid);
    }
    else {
        lt->tmr.expires = jiffies + msecs_to_jiffies (TTP_TMX_OPEN_SENT);
        add_timer (&lt->tmr);
        TTP_EVLOG (ev, TTP_LG__SH_TIMER_START, TTP_OP__invalid);
    }
    return true;
}

/* CLOSE_SENT: Start timer */
TTP_NOINLINE
static bool ttp_fsm_sef__EMPTY_NOCQ (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx\n", __FUNCTION__, cpu_to_be64 (ev->kid));

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    lt->state = TTP_ST__CLOSE_SENT;
    if (!lt->close_tx_id) {
        lt->close_tx_id = lt->tx_seq_id;
        lt->close_rx_id = lt->rx_seq_id;
        lt->peer_close_tx_id = 0;
        lt->close_ack_pending = false;
        lt->close_ack_sent = false;
    }
    return true;
}

static void ttp_fsm_enqueue_internal (u64 kid, enum ttp_events_enum evt)
{
    struct ttp_fsm_event *ev;

    if (!ttp_evt_pget (&ev)) {
        return;
    }

    ev->evt = evt;
    ev->kid = kid;
    ttp_evt_enqu (ev);
}

/* OPEN_RECD: Allocate Tag */
TTP_NOINLINE
static bool ttp_fsm_sef__TAG_ALLOC (struct ttp_fsm_event *ev)
{
    int rv;
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, ev->psi.rxi_seq, ev->psi.txi_seq);

    ttp_bloom_add (ev->kid);

    rv = ttp_tag_add (ev->kid);
    if (0 == rv) {
        ev->evt = TTP_EV__INQ__ALLOC_TAG;
        lt = ttp_rbtree_tag_get (ev->kid);
        lt->rx_seq_id = ev->psi.txi_seq; /* init tag-rx-seq-id with OPEN's tx-seq-id */
        lt->state = TTP_ST__OPEN_RECD;
        rv = ttpoe_socket_accept_prepare (ev->kid);
        if (rv < 0) {
            ev->evt = TTP_EV__INQ__NO_TAG;
        }
    }
    else if (1 == rv) {
        ev->evt = TTP_EV__INQ__NO_TAG;
    }
    else {
        ev->evt = TTP_EV__INQ__NO_TAG;
    }

    ttp_evt_cpqu (ev);
    return true;
}

/* CLOSE_RECD: Start quiesce */
TTP_NOINLINE
static bool ttp_fsm_sef__QUIESCE_START (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d\n", __FUNCTION__, cpu_to_be64 (ev->kid), ev->idx);

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    lt->state = TTP_ST__CLOSE_RECD;
    if (lt->close_ack_pending && !lt->close_ack_sent && ttp_tag_is_quiesced (lt)) {
        ttp_fsm_enqueue_internal (ev->kid, TTP_EV__INQ__YES_QUIESCED);
    }
    else {
        ttp_fsm_enqueue_internal (ev->kid, TTP_EV__INQ__NOT_QUIESCED);
    }
    return true;
}

char *ttp_sef_names[] =
{
    [TTP_ST__stay]       = "__none__",
    [TTP_ST__CLOSED]     = "__none__",
    [TTP_ST__OPEN_SENT]  = "OPEN_TIMER",
    [TTP_ST__OPEN_RECD]  = "TAG_ALLOC",
    [TTP_ST__OPEN]       = "CHECK_NOC",
    [TTP_ST__CLOSE_SENT] = "EMPTY_NOC",
    [TTP_ST__CLOSE_RECD] = "QUIESCE_START",
    [TTP_ST__invalid]    = "__invalid__",
};

ttp_fsm_fn ttp_fsm_entry_function[] =
{
    [TTP_ST__stay]       = NULL,
    [TTP_ST__CLOSED]     = ttp_fsm_sef__TAG_RESET,
    [TTP_ST__OPEN_SENT]  = ttp_fsm_sef__OPEN_TIMER,
    [TTP_ST__OPEN_RECD]  = ttp_fsm_sef__TAG_ALLOC,
    [TTP_ST__OPEN]       = ttp_fsm_sef__CHECK_NOC,
    [TTP_ST__CLOSE_SENT] = ttp_fsm_sef__EMPTY_NOCQ,
    [TTP_ST__CLOSE_RECD] = ttp_fsm_sef__QUIESCE_START,
    [TTP_ST__invalid]    = NULL,
};


enum ttp_opcodes_enum ttp_fsm_response_op[TTP_RS__NUM_EV] =
{
    [TTP_RS__none]         = TTP_OP__invalid,
    [TTP_RS__OPEN]         = TTP_OP__TTP_OPEN,
    [TTP_RS__OPEN_ACK]     = TTP_OP__TTP_OPEN_ACK,
    [TTP_RS__OPEN_NACK]    = TTP_OP__TTP_OPEN_NACK,
    [TTP_RS__CLOSE]        = TTP_OP__TTP_CLOSE,
    [TTP_RS__CLOSE_ACK]    = TTP_OP__TTP_CLOSE_ACK,
    [TTP_RS__CLOSE_NACK]   = TTP_OP__TTP_CLOSE_NACK,
    [TTP_RS__CLOSE_XACK]   = TTP_OP__TTP_CLOSE_ACK,
    [TTP_RS__REPLAY_DATA]  = TTP_OP__TTP_PAYLOAD,
    [TTP_RS__PAYLOAD]      = TTP_OP__TTP_PAYLOAD,
    [TTP_RS__PAYLOAD2]     = TTP_OP__TTP_PAYLOAD,
    [TTP_RS__ACK]          = TTP_OP__TTP_ACK,
    [TTP_RS__NACK]         = TTP_OP__TTP_NACK,
    [TTP_RS__NACK_NOLINK]  = TTP_OP__TTP_NACK_NOLINK,
    [TTP_RS__NOC_FAIL]     = TTP_OP__invalid,
    [TTP_RS__NOC_END]      = TTP_OP__invalid,
    [TTP_RS__ILLEGAL]      = TTP_OP__invalid,
    [TTP_RS__INTERRUPT]    = TTP_OP__invalid,
    [TTP_RS__DROP]         = TTP_OP__invalid,
    [TTP_RS__STALL]        = TTP_OP__invalid,
};


enum ttp_events_enum ttp_opcodes_to_events_map[TTP_OP__NUM_OP] = {
    [TTP_OP__TTP_OPEN]         = TTP_EV__RXQ__TTP_OPEN,
    [TTP_OP__TTP_OPEN_ACK]     = TTP_EV__RXQ__TTP_OPEN_ACK,
    [TTP_OP__TTP_OPEN_NACK]    = TTP_EV__RXQ__TTP_OPEN_NACK,
    [TTP_OP__TTP_CLOSE]        = TTP_EV__RXQ__TTP_CLOSE,
    [TTP_OP__TTP_CLOSE_ACK]    = TTP_EV__RXQ__TTP_CLOSE_ACK,
    [TTP_OP__TTP_CLOSE_NACK]   = TTP_EV__RXQ__TTP_CLOSE_NACK,
    [TTP_OP__TTP_PAYLOAD]      = TTP_EV__RXQ__TTP_PAYLOAD,
    [TTP_OP__TTP_ACK]          = TTP_EV__RXQ__TTP_ACK,
    [TTP_OP__TTP_NACK]         = TTP_EV__RXQ__TTP_NACK,
    [TTP_OP__TTP_NACK_FULL]    = TTP_EV__RXQ__TTP_NACK_FULL,
    [TTP_OP__TTP_NACK_NOLINK]  = TTP_EV__RXQ__TTP_NACK_NOLINK,
};


#define TTP_FSM_RS__common(foo, op)                       \
    ttp_fsm_rs__##foo (struct ttp_fsm_event *ev)          \
    {                                                     \
        struct sk_buff *skb;                              \
        struct ttp_link_tag *lt;                          \
        struct ttp_frame_hdr frh;                         \
                                                          \
        lt = ttp_rbtree_tag_get (ev->kid);                \
                                                          \
        if (!ttp_skb_prep (&skb, ev, op)) {               \
            TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);         \
            return false;                                 \
        }                                                 \
                                                          \
        ttp_skb_pars (skb, &frh, NULL);                   \
        if (lt)                                           \
            ev->psi.rxi_seq = lt->rx_seq_id;              \
        ev->psi.txi_seq = 0;                              \
                                                          \
        frh.ttp->conn_rx_seq = htonl (ev->psi.rxi_seq);   \
        frh.ttp->conn_tx_seq = 0; /* tx=0 for ACKs */     \
                                                          \
        ttp_skb_xmit (skb);                               \
        TTP_EVLOG (ev, TTP_LG__PKT_TX, op);               \
                                                          \
        TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n",       \
                 __FUNCTION__,                            \
                 cpu_to_be64 (ev->kid), ev->idx,          \
                 TTP_OPCODE_NAME (op));                   \
        return true;                                      \
    }


static bool TTP_FSM_RS__common  (OPEN_ACK,    ttp_fsm_response_op[TTP_RS__OPEN_ACK   ]);
static bool TTP_FSM_RS__common  (OPEN_NACK,   ttp_fsm_response_op[TTP_RS__OPEN_NACK  ]);
static bool TTP_FSM_RS__common  (NACK,        ttp_fsm_response_op[TTP_RS__NACK       ]);
static bool TTP_FSM_RS__common  (NACK_NOLINK, ttp_fsm_response_op[TTP_RS__NACK_NOLINK]);

static bool ttp_fsm_close_replay_ready (struct ttp_link_tag *lt)
{
    if (!lt->close_blocked) {
        return true;
    }

    if (!lt->close_tx_id) {
        return true;
    }

    if (ttp_seq_geq_u32 (ttp_seq_next_u32 (lt->retire_id), lt->close_tx_id)) {
        return true;
    }

    if (!ttp_tag_has_pending_noc (lt)) {
        return true;
    }

    return false;
}

static u32 ttp_fsm_local_close_tx_id (struct ttp_link_tag *lt)
{
    return lt->close_tx_id ? lt->close_tx_id : lt->tx_seq_id;
}

static u32 ttp_fsm_local_close_rx_id (struct ttp_link_tag *lt)
{
    return lt->close_rx_id ? lt->close_rx_id : lt->rx_seq_id;
}

static bool ttp_fsm_close_need_nack (struct ttp_link_tag *lt, struct ttp_fsm_event *ev)
{
    u32 local_tx = ttp_fsm_local_close_tx_id (lt);

    if (TTP_ST__CLOSE_SENT == lt->state) {
        return ttp_seq_after_u32 (ev->psi.rxi_seq, ttp_seq_next_u32 (local_tx));
    }

    if (TTP_ST__OPEN == lt->state || TTP_ST__CLOSE_RECD == lt->state) {
        return ttp_seq_after_u32 (ev->psi.rxi_seq, local_tx);
    }

    return false;
}

static u32 ttp_fsm_local_closing_rx_limit (struct ttp_link_tag *lt)
{
    return lt->close_rx_id ? lt->close_rx_id : lt->rx_seq_id;
}


TTP_NOINLINE
static bool ttp_fsm_rs__OPEN (struct ttp_fsm_event *ev)
{
    struct sk_buff *skb;
    struct ttp_link_tag *lt;
    struct ttp_frame_hdr frh;
    enum ttp_opcodes_enum op = TTP_OP__TTP_OPEN;

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    if (!ttp_skb_prep (&skb, ev, op)) {
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);

    ev->psi.rxi_seq = lt->rx_seq_id;
    frh.ttp->conn_rx_seq = htonl (ev->psi.rxi_seq);

    /* resend OPEN e.g. to handle NACK_NOLINK from peer, or duplicate TXQ_OPEN */
    ev->psi.txi_seq = lt->retire_id;
    frh.ttp->conn_tx_seq = htonl (ev->psi.txi_seq);

    lt->open_tx_pending = true;
    atomic_inc (&lt->opens);
    ttp_skb_xmit (skb);
    TTP_EVLOG (ev, TTP_LG__PKT_TX, op);

    TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, TTP_OPCODE_NAME (op));
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_rs__CLOSE (struct ttp_fsm_event *ev)
{
    struct sk_buff *skb;
    struct ttp_link_tag *lt;
    struct ttp_frame_hdr frh;
    enum ttp_opcodes_enum op = TTP_OP__TTP_CLOSE;

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    if (!lt->close_tx_id) {
        lt->close_tx_id = lt->tx_seq_id;
        lt->close_rx_id = lt->rx_seq_id;
    }

    if (lt->close_blocked && !ttp_fsm_close_replay_ready (lt)) {
        if (timer_pending (&lt->tmr)) {
            mod_timer_pending (&lt->tmr, jiffies + msecs_to_jiffies (TTP_TMX_CLOSE_SENT));
            TTP_EVLOG (ev, TTP_LG__LN_TIMER_RESTART, TTP_OP__invalid);
        }
        else {
            lt->tmr.expires = jiffies + msecs_to_jiffies (TTP_TMX_CLOSE_SENT);
            add_timer (&lt->tmr);
            TTP_EVLOG (ev, TTP_LG__LN_TIMER_START, TTP_OP__invalid);
        }
        return true;
    }
    lt->close_blocked = false;
    lt->close_nack_rx_id = 0;

    if (!ttp_skb_prep (&skb, ev, op)) {
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);

    ev->psi.rxi_seq = lt->close_rx_id;
    ev->psi.txi_seq = lt->close_tx_id;
    frh.ttp->conn_rx_seq = htonl (lt->close_rx_id);
    frh.ttp->conn_tx_seq = htonl (lt->close_tx_id);

    ttp_skb_xmit (skb);
    TTP_EVLOG (ev, TTP_LG__PKT_TX, op);

    if (timer_pending (&lt->tmr)) {
        mod_timer_pending (&lt->tmr, jiffies + msecs_to_jiffies (TTP_TMX_CLOSE_SENT));
        TTP_EVLOG (ev, TTP_LG__LN_TIMER_RESTART, TTP_OP__invalid);
    }
    else {
        lt->tmr.expires = jiffies + msecs_to_jiffies (TTP_TMX_CLOSE_SENT);
        add_timer (&lt->tmr);
        TTP_EVLOG (ev, TTP_LG__LN_TIMER_START, TTP_OP__invalid);
    }

    TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, TTP_OPCODE_NAME (op));
    return true;
}

TTP_NOINLINE
static bool ttp_fsm_rs__CLOSE_NACK (struct ttp_fsm_event *ev)
{
    struct sk_buff *skb;
    struct ttp_link_tag *lt;
    struct ttp_frame_hdr frh;
    enum ttp_opcodes_enum op = TTP_OP__TTP_CLOSE_NACK;
    u32 tx_id, rx_id;

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    if (!ttp_skb_prep (&skb, ev, op)) {
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);

    tx_id = ttp_fsm_local_close_tx_id (lt);
    rx_id = ttp_fsm_local_close_rx_id (lt);
    ev->psi.txi_seq = tx_id;
    ev->psi.rxi_seq = rx_id;

    frh.ttp->conn_tx_seq = htonl (tx_id);
    frh.ttp->conn_rx_seq = htonl (rx_id);

    ttp_skb_xmit (skb);
    TTP_EVLOG (ev, TTP_LG__PKT_TX, op);

    TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, TTP_OPCODE_NAME (op));
    return true;
}

TTP_NOINLINE
static bool ttp_fsm_rs__CLOSE_ACK (struct ttp_fsm_event *ev)
{
    struct sk_buff *skb;
    struct ttp_link_tag *lt;
    struct ttp_frame_hdr frh;
    enum ttp_opcodes_enum op = TTP_OP__TTP_CLOSE_ACK;
    u32 rx_id = ev->psi.rxi_seq;

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    if (!ttp_skb_prep (&skb, ev, op)) {
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);

    if (lt->peer_close_tx_id) {
        rx_id = lt->peer_close_tx_id;
    }

    ev->psi.rxi_seq = rx_id;
    ev->psi.txi_seq = 0;
    frh.ttp->conn_rx_seq = htonl (rx_id);
    frh.ttp->conn_tx_seq = 0;

    ttp_skb_xmit (skb);
    TTP_EVLOG (ev, TTP_LG__PKT_TX, op);

    lt->close_ack_pending = false;
    lt->close_ack_sent = true;

    TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, TTP_OPCODE_NAME (op));
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_rs__CLOSE_XACK (struct ttp_fsm_event *ev)
{
    struct sk_buff *skb;
    struct ttp_link_tag *lt;
    struct ttp_frame_hdr frh;
    enum ttp_opcodes_enum op = TTP_OP__TTP_CLOSE_ACK;

    if (ev->tx_flags & TTP_NOC_TXF_CLOSE_NACK) {
        return ttp_fsm_rs__CLOSE_NACK (ev);
    }

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    if (!ttp_skb_prep (&skb, ev, op)) {
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);

    frh.ttp->conn_rx_seq = htonl (ev->psi.rxi_seq);
    frh.ttp->conn_tx_seq = ev->psi.txi_seq = 0; /* tx-id=0 for ACKs */

    ttp_skb_xmit (skb);
    TTP_EVLOG (ev, TTP_LG__PKT_TX, op);

    TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, TTP_OPCODE_NAME (op));
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_rs__ACK (struct ttp_fsm_event *ev)
{
    int rv;
    struct sk_buff *skb;
    struct ttp_link_tag *lt;
    struct ttp_frame_hdr frh;
    struct ttp_pkt_info  pif = {0};
    enum ttp_opcodes_enum op = TTP_OP__TTP_ACK;
    u32 ack_seq = 0;

    ttp_skb_pars (ev->rsk, &frh, &pif);

    TTP_DB1 ("%s: 0x%016llx.%d len: %d\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, pif.noc_len);

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        op = TTP_OP__TTP_NACK_NOLINK;

        TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_DROP, op);
        TTP_DBG ("%s: opcode:%s 0x%016llx.%d *** TAG NOT FOUND ***\n",
                 __FUNCTION__, TTP_OPCODE_NAME (op), cpu_to_be64 (ev->kid), ev->idx);
        atomic_inc (&ttp_stats.drp_ct);
        return false;
    }

    if (!pif.noc_len) {
        op = TTP_OP__TTP_NACK;
        goto send;              /* no payload to copy */
    }

/*
 * Per TTP_Opcode spec:-
 * [OPEN] / [CLOSE_SENT] / [CLOSE_RECD]
 *      TTP_ACK         TxID <= local RxID
 *      TTP_NACK        TxID >  local RxID
 *      TTP_NACK_FULL   local is temporarily full
 * [CLOSE_SENT] / [CLOSE_RECD]
 *      TTP_NACK_NOLINK TxID >  local closing ID
 */
    if (TTP_ST__OPEN == lt->state ||
        TTP_ST__CLOSE_SENT == lt->state || TTP_ST__CLOSE_RECD == lt->state) {
        u32 expected_seq = ttp_seq_next_u32 (lt->rx_seq_id);
        u32 close_limit = ttp_fsm_local_closing_rx_limit (lt);

        if ((TTP_ST__CLOSE_SENT == lt->state || TTP_ST__CLOSE_RECD == lt->state) &&
            ttp_seq_after_u32 (pif.txi_seq, close_limit)) {
            op = TTP_OP__TTP_NACK_NOLINK;
            ack_seq = close_limit;

            TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_DROP, op);
            TTP_DB1 ("`-> %s: NACK_NOLINK seq-id:%d (close-limit:%d)\n",
                     __FUNCTION__, pif.txi_seq, close_limit);
            atomic_inc (&ttp_stats.drp_ct);
        }
        else if (expected_seq == pif.txi_seq) {
            rv = ttpoe_socket_payload_rx (ev->kid, (u8 *)frh.noc, pif.noc_len);
            if (-ENOTCONN == rv && !lt->sock_managed) {
                rv = ttpoe_noc_debug_rx ((u8 *)frh.noc, pif.noc_len);
            }
            else if (-EPROTO == rv || -EINVAL == rv) {
                atomic_inc (&ttp_stats.drp_ct);
                TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_DROP, TTP_OP__TTP_NACK);
                op = TTP_OP__TTP_NACK;
                goto send;
            }
            else if (-ENOTCONN == rv) {
                atomic_inc (&ttp_stats.drp_ct);
                TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_DROP, TTP_OP__TTP_NACK_FULL);
            }
            if (rv) {
                op = TTP_OP__TTP_NACK_FULL;
                goto send;
            }

            op = TTP_OP__TTP_ACK;
            lt->rx_seq_id++;    /* update tag-rx-seq-id */
            ack_seq = pif.txi_seq;

            TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_RX, op);
            TTP_DB1 ("`-> %s: ACK payload seq-id:%d (exp:%d+1)\n",
                     __FUNCTION__, pif.txi_seq, lt->rx_seq_id);
            atomic_inc (&ttp_stats.pld_ct);
        }
        else if (pif.txi_seq && ttp_seq_before_u32 (pif.txi_seq, expected_seq)) {
            op = TTP_OP__TTP_ACK;
            ack_seq = pif.txi_seq;

            TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_DUP, op);
            TTP_DB1 ("`-> %s: ACK duplicate seq-id:%d (exp:%d+1)\n",
                     __FUNCTION__, pif.txi_seq, lt->rx_seq_id);
            atomic_inc (&ttp_stats.drp_ct);
        }
        else if (ttp_seq_before_u32 (lt->rx_seq_id, pif.txi_seq)) {
            op = TTP_OP__TTP_NACK;
            ack_seq = expected_seq;

            TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_DROP, op);
            TTP_DB1 ("`-> %s: NACK future seq-id:%d (exp:%d+1)\n",
                     __FUNCTION__, pif.txi_seq, lt->rx_seq_id);
            atomic_inc (&ttp_stats.drp_ct);
        }
        else {
            op = TTP_OP__TTP_NACK;
            ack_seq = expected_seq;

            TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_DROP, op);
            TTP_DB1 ("`-> %s: NACK *UNEXPECTED* seq-id:%d (exp:%d+1)\n",
                     __FUNCTION__, pif.txi_seq, lt->rx_seq_id);
            atomic_inc (&ttp_stats.drp_ct);
        }
    }

send:
    if (!ttp_skb_prep (&skb, ev, op)) {
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);

    ev->psi.rxi_seq = ack_seq ? ack_seq : lt->rx_seq_id;
    frh.ttp->conn_rx_seq = htonl (ev->psi.rxi_seq);
    frh.ttp->conn_tx_seq = ev->psi.txi_seq = 0; /* tx-id=0 for ACKs */

    ttp_skb_xmit (skb);
    TTP_EVLOG (ev, TTP_LG__PKT_TX, op);

    TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, TTP_OPCODE_NAME (op));
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_rs__REPLAY_DATA (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d\n", __FUNCTION__, cpu_to_be64 (ev->kid), ev->idx);

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }

    ttp_noc_mark_timeout (lt);
    ttp_noc_requ (lt);
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_rs__PAYLOAD (struct ttp_fsm_event *ev)
{
    struct sk_buff *skb;
    struct ttp_link_tag *lt;
    struct ttp_frame_hdr frh;
    enum ttp_opcodes_enum op = TTP_OP__TTP_PAYLOAD;

    TTP_DB1 ("%s: 0x%016llx.%d (len: %d)\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, ev->psi.noc_len);

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }
    if (!ev->psi.noc_len) {
        return false;
    }
    if (!ttp_skb_prep (&skb, ev, op)) {
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);

    frh.ttp->conn_rx_seq = ev->psi.rxi_seq = 0; /* rx=0 for PAYLOAD */
    frh.ttp->conn_tx_seq = htonl (ev->psi.txi_seq);

    if (ttp_rnd_flip (0)) {  /* with p% random drop */
        ttp_skb_drop (skb);
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
    }
    else {
        ttp_skb_xmit (skb);
        TTP_EVLOG (ev, TTP_LG__PKT_TX, op);
    }

    if (ev->psi.txi_seq == lt->base_seq) {
        if (timer_pending (&lt->tmr)) {
            mod_timer_pending (&lt->tmr, jiffies + msecs_to_jiffies (TTP_TMX_PAYLOAD_SENT));
            TTP_EVLOG (ev, TTP_LG__LN_TIMER_RESTART, TTP_OP__invalid);
        }
        else {
            lt->tmr.expires = jiffies + msecs_to_jiffies (TTP_TMX_PAYLOAD_SENT);
            add_timer (&lt->tmr);
            TTP_EVLOG (ev, TTP_LG__LN_TIMER_START, TTP_OP__invalid);
        }
    }

    TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, TTP_OPCODE_NAME (op));
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_rs__PAYLOAD2 (struct ttp_fsm_event *ev)
{
    struct sk_buff *skb;
    struct ttp_link_tag *lt;
    struct ttp_frame_hdr frh;
    enum ttp_opcodes_enum op = TTP_OP__TTP_PAYLOAD;

    TTP_DB1 ("%s: 0x%016llx\n", __FUNCTION__, cpu_to_be64 (ev->kid));

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        return false;
    }
    if (!ev->psi.noc_len) {
        return false;
    }

    /* Send until TxID > remote closing ID, then stall */
    if (ttp_seq_after_u32 (ev->psi.txi_seq, lt->rx_seq_id)) {
        return false;
    }

    if (!ttp_skb_prep (&skb, ev, op)) {
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);

    frh.ttp->conn_rx_seq = ev->psi.rxi_seq = 0; /* rx=0 for PAYLOAD */
    frh.ttp->conn_tx_seq = ntohl (ev->psi.txi_seq);

    if (ttp_rnd_flip (0)) {  /* with p% random drop */
        ttp_skb_drop (skb);
        TTP_EVLOG (ev, TTP_LG__PKT_DROP, op);
    }
    else {
        ttp_skb_xmit (skb);
        TTP_EVLOG (ev, TTP_LG__PKT_TX, op);
    }

    if (ev->psi.txi_seq == lt->base_seq) {
        if (timer_pending (&lt->tmr)) {
            mod_timer_pending (&lt->tmr, jiffies + msecs_to_jiffies (TTP_TMX_PAYLOAD2_SENT));
            TTP_EVLOG (ev, TTP_LG__LN_TIMER_RESTART, TTP_OP__invalid);
        }
        else {
            lt->tmr.expires = jiffies + msecs_to_jiffies (TTP_TMX_PAYLOAD2_SENT);
            add_timer (&lt->tmr);
            TTP_EVLOG (ev, TTP_LG__LN_TIMER_START, TTP_OP__invalid);
        }
    }

    TTP_DB1 ("%s: 0x%016llx.%d <<Sent: %s<<\n", __FUNCTION__,
             cpu_to_be64 (ev->kid), ev->idx, TTP_OPCODE_NAME (op));
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_rs__DROP (struct ttp_fsm_event *ev)
{
    TTP_DB1 ("%s: 0x%016llx.%d\n", __FUNCTION__, cpu_to_be64 (ev->kid), ev->idx);
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_rs__INTERRUPT (struct ttp_fsm_event *ev)
{
    TTP_DB1 ("%s: 0x%016llx.%d\n", __FUNCTION__, cpu_to_be64 (ev->kid), ev->idx);
    return true;
}


ttp_fsm_fn ttp_fsm_response_fn[TTP_RS__NUM_EV] =
{
    [TTP_RS__OPEN]         = ttp_fsm_rs__OPEN,
    [TTP_RS__OPEN_ACK]     = ttp_fsm_rs__OPEN_ACK,
    [TTP_RS__OPEN_NACK]    = ttp_fsm_rs__OPEN_NACK,
    [TTP_RS__CLOSE]        = ttp_fsm_rs__CLOSE,
    [TTP_RS__CLOSE_ACK]    = ttp_fsm_rs__CLOSE_ACK,
    [TTP_RS__CLOSE_NACK]   = ttp_fsm_rs__CLOSE_NACK,
    [TTP_RS__CLOSE_XACK]   = ttp_fsm_rs__CLOSE_XACK,
    [TTP_RS__REPLAY_DATA]  = ttp_fsm_rs__REPLAY_DATA,
    [TTP_RS__PAYLOAD]      = ttp_fsm_rs__PAYLOAD,
    [TTP_RS__PAYLOAD2]     = ttp_fsm_rs__PAYLOAD2,
    [TTP_RS__ACK]          = ttp_fsm_rs__ACK,
    [TTP_RS__NACK]         = ttp_fsm_rs__NACK,
    [TTP_RS__NACK_NOLINK]  = ttp_fsm_rs__NACK_NOLINK,
    [TTP_RS__DROP]         = ttp_fsm_rs__DROP,
    [TTP_RS__INTERRUPT]    = ttp_fsm_rs__INTERRUPT,
};


TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_OPEN (struct ttp_fsm_event *qev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if ((lt = ttp_rbtree_tag_get (qev->kid))) {
        lt->rx_seq_id = qev->psi.txi_seq; /* init tag-rx-seq-id with OPEN's tx-seq-id */
        if (TTP_ST__OPEN_SENT == lt->state) {
            lt->open_tx_pending = false;
        }
        if (TTP_ST__OPEN_RECD == lt->state) {
            qev->fsm_override = 1;
            qev->fsm_response = TTP_RS__OPEN_ACK;
            qev->fsm_next_state = TTP_ST__stay;
        }
        TTP_DB1 ("`-> found existing tag (dup TTP_OPEN)\n");
    }
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_OPEN_ACK (struct ttp_fsm_event *qev)
{
    int tv;
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    lt->retire_id = qev->psi.rxi_seq; /* store seq-id open (got in ACK as rxi-seq) */
    if (lt->open_tx_pending) {
        lt->open_tx_pending = false;
        if (TTP_ST__OPEN_RECD == lt->state) {
            qev->fsm_override = 1;
            qev->fsm_response = TTP_RS__none;
            qev->fsm_next_state = TTP_ST__OPEN;
        }
    }

    if (timer_pending (&lt->tmr)) {
        tv = del_timer (&lt->tmr);
        TTP_EVLOG (qev, TTP_LG__TIMER_DELETE, TTP_OP__TTP_OPEN_ACK);
    }
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_OPEN_NACK (struct ttp_fsm_event *qev)
{
    int tv;
    struct ttp_link_tag *lt;

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    lt->open_tx_pending = false;
    if (timer_pending (&lt->tmr)) {
        tv = del_timer (&lt->tmr);
        (void)tv;
        TTP_EVLOG (qev, TTP_LG__TIMER_DELETE, TTP_OP__TTP_OPEN_NACK);
    }
    return true;
}


TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_ACK (struct ttp_fsm_event *qev)
{
    int tv;
    bool advanced = false;
    bool matched = false;
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    matched = ttp_noc_ack_seq (lt, qev->psi.rxi_seq, &advanced);
    if (!matched) {
        TTP_DB1 ("`-> %s: ack-rx:%d not pending\n", __FUNCTION__, qev->psi.rxi_seq);
    }

    if (advanced) {
        if (ttp_tag_has_pending_noc (lt)) {
            if (timer_pending (&lt->tmr)) {
                mod_timer_pending (&lt->tmr, jiffies + msecs_to_jiffies (TTP_TMX_PAYLOAD_SENT));
                TTP_EVLOG (qev, TTP_LG__LN_TIMER_RESTART, TTP_OP__TTP_ACK);
            }
            else {
                lt->tmr.expires = jiffies + msecs_to_jiffies (TTP_TMX_PAYLOAD_SENT);
                add_timer (&lt->tmr);
                TTP_EVLOG (qev, TTP_LG__LN_TIMER_START, TTP_OP__TTP_ACK);
            }
        }
        else if (timer_pending (&lt->tmr)) {
            tv = del_timer (&lt->tmr);
            (void)tv;
            TTP_EVLOG (qev, TTP_LG__TIMER_DELETE, TTP_OP__TTP_ACK);
        }
    }

    ttp_noc_requ (lt);
    return matched;
}


TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_NACK (struct ttp_fsm_event *qev)
{
    bool marked;
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    marked = ttp_noc_mark_retransmit_from (lt, qev->psi.rxi_seq);
    if (marked) {
        if (timer_pending (&lt->tmr)) {
            mod_timer_pending (&lt->tmr, jiffies + msecs_to_jiffies (TTP_TMX_PAYLOAD_SENT));
            TTP_EVLOG (qev, TTP_LG__LN_TIMER_RESTART, TTP_OP__TTP_NACK);
        }
        else {
            lt->tmr.expires = jiffies + msecs_to_jiffies (TTP_TMX_PAYLOAD_SENT);
            add_timer (&lt->tmr);
            TTP_EVLOG (qev, TTP_LG__LN_TIMER_START, TTP_OP__TTP_NACK);
        }
    }

    ttp_noc_requ (lt);
    return marked;
}

TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_CLOSE (struct ttp_fsm_event *qev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    if (ttp_fsm_close_need_nack (lt, qev)) {
        qev->tx_flags |= TTP_NOC_TXF_CLOSE_NACK;
        qev->fsm_override = 1;
        qev->fsm_response = TTP_RS__CLOSE_NACK;
        qev->fsm_next_state = TTP_ST__stay;
        return true;
    }

    lt->peer_close_tx_id = qev->psi.txi_seq;
    lt->close_ack_pending = true;
    lt->close_ack_sent = false;
    qev->fsm_override = 1;
    qev->fsm_response = TTP_RS__none;
    if (TTP_ST__CLOSE_RECD == lt->state) {
        qev->fsm_next_state = TTP_ST__stay;
        if (ttp_tag_is_quiesced (lt)) {
            ttp_fsm_enqueue_internal (qev->kid, TTP_EV__INQ__YES_QUIESCED);
        }
    }
    else {
        qev->fsm_next_state = TTP_ST__CLOSE_RECD;
    }
    return true;
}

TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_CLOSE_NACK (struct ttp_fsm_event *qev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    lt->close_nack_rx_id = qev->psi.rxi_seq;
    lt->close_blocked = true;
    if (ttp_fsm_close_replay_ready (lt)) {
        lt->close_blocked = false;
        lt->close_nack_rx_id = 0;
    }
    return true;
}

TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_NACK_FULL (struct ttp_fsm_event *qev)
{
    bool marked = false;
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    lt->full_blocked = true;
    if (lt->base_seq && ttp_seq_before_u32 (lt->base_seq, lt->tx_seq_id)) {
        if (lt->full_retry >= TTP_FULL_MAX_RETRY) {
            int dropped = lt->tct;

            ttpoe_socket_link_error (lt->_rkid, ETIMEDOUT);
            if (timer_pending (&lt->tmr)) {
                del_timer (&lt->tmr);
            }
            while (ttp_noc_dequ (lt)) {
                ;
            }
            ttp_stats.nocq -= dropped;
            ttp_tag_reset (lt);
            return true;
        }
        marked = ttp_noc_mark_retransmit_one (lt, lt->base_seq);
    }
    else if (!ttp_tag_has_pending_noc (lt)) {
        lt->full_blocked = false;
        lt->full_backoff_active = false;
        lt->full_retry = 0;
    }

    if (marked) {
        ttp_noc_start_full_backoff (lt, qev);
        lt->full_retry++;
    }
    else {
        lt->full_blocked = false;
        lt->full_backoff_active = false;
        lt->full_retry = 0;
    }

    return true;
}

TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_NACK_NOLINK (struct ttp_fsm_event *qev)
{
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    if (TTP_ST__OPEN == lt->state ||
        TTP_ST__OPEN_SENT == lt->state ||
        TTP_ST__OPEN_RECD == lt->state) {
        lt->open_tx_pending = true;
        qev->fsm_override = 1;
        qev->fsm_response = TTP_RS__OPEN;
        qev->fsm_next_state = TTP_ST__OPEN_SENT;
        return true;
    }

    if (TTP_ST__CLOSE_SENT == lt->state || TTP_ST__CLOSE_RECD == lt->state) {
        if (ttp_tag_is_quiesced (lt) || !ttp_tag_has_pending_noc (lt)) {
            qev->fsm_override = 1;
            qev->fsm_response = TTP_RS__NOC_END;
            qev->fsm_next_state = TTP_ST__CLOSED;
            return true;
        }

        qev->fsm_override = 1;
        qev->fsm_response = TTP_RS__none;
        qev->fsm_next_state = TTP_ST__stay;
        return true;
    }

    return true;
}


TTP_NOINLINE
static bool ttp_fsm_ev_hdl__RXQ__TTP_PAYLOAD (struct ttp_fsm_event *qev)
{
    int tv;
    struct ttp_link_tag *lt;

    TTP_DB1 ("%s: 0x%016llx.%d: rx:%d tx:%d\n", __FUNCTION__,
             cpu_to_be64 (qev->kid), qev->idx, qev->psi.rxi_seq, qev->psi.txi_seq);

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        return false;
    }

    if (timer_pending (&lt->tmr)) {
        tv = del_timer (&lt->tmr);
        TTP_EVLOG (qev, TTP_LG__TIMER_DELETE, TTP_OP__TTP_PAYLOAD);
    }
    return true;
}


ttp_fsm_fn ttp_fsm_event_handle_fn[TTP_EV__NUM_EV] =
{
    [TTP_EV__RXQ__TTP_OPEN]     = ttp_fsm_ev_hdl__RXQ__TTP_OPEN,
    [TTP_EV__RXQ__TTP_OPEN_ACK] = ttp_fsm_ev_hdl__RXQ__TTP_OPEN_ACK,
    [TTP_EV__RXQ__TTP_OPEN_NACK] = ttp_fsm_ev_hdl__RXQ__TTP_OPEN_NACK,
    [TTP_EV__RXQ__TTP_CLOSE]    = ttp_fsm_ev_hdl__RXQ__TTP_CLOSE,
    [TTP_EV__RXQ__TTP_CLOSE_NACK] = ttp_fsm_ev_hdl__RXQ__TTP_CLOSE_NACK,
    [TTP_EV__RXQ__TTP_ACK]      = ttp_fsm_ev_hdl__RXQ__TTP_ACK,
    [TTP_EV__RXQ__TTP_NACK]     = ttp_fsm_ev_hdl__RXQ__TTP_NACK,
    [TTP_EV__RXQ__TTP_NACK_FULL] = ttp_fsm_ev_hdl__RXQ__TTP_NACK_FULL,
    [TTP_EV__RXQ__TTP_NACK_NOLINK] = ttp_fsm_ev_hdl__RXQ__TTP_NACK_NOLINK,
    [TTP_EV__RXQ__TTP_PAYLOAD]  = ttp_fsm_ev_hdl__RXQ__TTP_PAYLOAD,
    /* all other handlers are NULL */
};


/*           Next-State__RESPONSE          Response enum                      Next State enum                  */
#define          _no_rs__no_ns_         { .response = TTP_RS__none        ,  .next_state = TTP_ST__stay       , }
#define         rs_none__ns_stay        { .response = TTP_RS__none        ,  .next_state = TTP_ST__stay       , }
#define      rs_PAYLOAD__ns_stay        { .response = TTP_RS__PAYLOAD     ,  .next_state = TTP_ST__stay       , }
#define     rs_PAYLOAD2__ns_stay        { .response = TTP_RS__PAYLOAD2    ,  .next_state = TTP_ST__stay       , }
#define        rs_STALL__ns_stay        { .response = TTP_RS__STALL       ,  .next_state = TTP_ST__stay       , }
#define         rs_OPEN__ns_stay        { .response = TTP_RS__OPEN        ,  .next_state = TTP_ST__stay       , }
#define      rs_ILLEGAL__ns_stay        { .response = TTP_RS__ILLEGAL     ,  .next_state = TTP_ST__stay       , }
#define    rs_INTERRUPT__ns_stay        { .response = TTP_RS__INTERRUPT   ,  .next_state = TTP_ST__stay       , }
#define         rs_DROP__ns_stay        { .response = TTP_RS__DROP        ,  .next_state = TTP_ST__stay       , }
#define        rs_CLOSE__ns_stay        { .response = TTP_RS__CLOSE       ,  .next_state = TTP_ST__stay       , }
#define          rs_ACK__ns_stay        { .response = TTP_RS__ACK         ,  .next_state = TTP_ST__stay       , }
#define         rs_NACK__ns_stay        { .response = TTP_RS__NACK        ,  .next_state = TTP_ST__stay       , }
#define    rs_OPEN_NACK__ns_stay        { .response = TTP_RS__OPEN_NACK   ,  .next_state = TTP_ST__stay       , }
#define     rs_OPEN_ACK__ns_stay        { .response = TTP_RS__OPEN_ACK    ,  .next_state = TTP_ST__stay       , }
#define  rs_NACK_NOLINK__ns_stay        { .response = TTP_RS__NACK_NOLINK ,  .next_state = TTP_ST__stay       , }
#define   rs_CLOSE_XACK__ns_stay        { .response = TTP_RS__CLOSE_XACK  ,  .next_state = TTP_ST__stay       , }
#define   rs_CLOSE_NACK__ns_stay        { .response = TTP_RS__CLOSE_NACK  ,  .next_state = TTP_ST__stay       , }
#define    rs_CLOSE_ACK__ns_stay        { .response = TTP_RS__CLOSE_ACK   ,  .next_state = TTP_ST__stay       , }
#define  rs_REPLAY_DATA__ns_stay        { .response = TTP_RS__REPLAY_DATA ,  .next_state = TTP_ST__stay       , }
#define        rs_CLOSE__ns_CLOSED      { .response = TTP_RS__CLOSE       ,  .next_state = TTP_ST__CLOSED     , }
#define    rs_CLOSE_ACK__ns_CLOSED      { .response = TTP_RS__CLOSE_ACK   ,  .next_state = TTP_ST__CLOSED     , }
#define    rs_CLOSE_ACK__ns_CLOSE_RECD  { .response = TTP_RS__CLOSE_ACK   ,  .next_state = TTP_ST__CLOSE_RECD , }
#define   rs_CLOSE_XACK__ns_CLOSE_RECD  { .response = TTP_RS__CLOSE_XACK  ,  .next_state = TTP_ST__CLOSE_RECD , }
#define     rs_NOC_FAIL__ns_CLOSED      { .response = TTP_RS__NOC_FAIL    ,  .next_state = TTP_ST__CLOSED     , }
#define      rs_NOC_END__ns_CLOSED      { .response = TTP_RS__NOC_END     ,  .next_state = TTP_ST__CLOSED     , }
#define    rs_OPEN_NACK__ns_CLOSED      { .response = TTP_RS__OPEN_NACK   ,  .next_state = TTP_ST__CLOSED     , }
#define      rs_NOC_END__ns_CLOSE_RECD  { .response = TTP_RS__NOC_END     ,  .next_state = TTP_ST__CLOSE_RECD , }
#define         rs_none__ns_CLOSE_SENT  { .response = TTP_RS__none        ,  .next_state = TTP_ST__CLOSE_SENT , }
#define         rs_none__ns_CLOSE_RECD  { .response = TTP_RS__none        ,  .next_state = TTP_ST__CLOSE_RECD , }
#define        rs_CLOSE__ns_CLOSE_SENT  { .response = TTP_RS__CLOSE       ,  .next_state = TTP_ST__CLOSE_SENT , }
#define     rs_OPEN_ACK__ns_OPEN        { .response = TTP_RS__OPEN_ACK    ,  .next_state = TTP_ST__OPEN       , }
#define         rs_none__ns_OPEN        { .response = TTP_RS__none        ,  .next_state = TTP_ST__OPEN       , }
#define         rs_none__ns_CLOSED      { .response = TTP_RS__none        ,  .next_state = TTP_ST__CLOSED     , }
#define         rs_none__ns_OPEN_RECD   { .response = TTP_RS__none        ,  .next_state = TTP_ST__OPEN_RECD  , }
#define         rs_OPEN__ns_OPEN_SENT   { .response = TTP_RS__OPEN        ,  .next_state = TTP_ST__OPEN_SENT  , }
#define         rs_OPEN__ns_OPEN        { .response = TTP_RS__OPEN        ,  .next_state = TTP_ST__OPEN       , }


struct ttp_fsm_state_var ttp_fsm_table[TTP_EV__NUM_EV][TTP_ST__NUM_ST] = /*                       sef:OPEN_TIMER                     sef:TAG_ALLOC                sef:CHECK_NOC                   sef:EMPTY_NOT                   sef:QUIESCE_START            */
{   /*                                                                 CLOSED                         OPEN_SENT                         OPEN_RECD                      OPEN                           CLOSE_SENT                        CLOSE_RECD             */
    [TTP_EV__TXQ__TTP_OPEN]        = { _no_rs__no_ns_  ,          rs_OPEN__ns_OPEN_SENT   ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_OPEN__ns_stay        ,      rs_ILLEGAL__ns_stay       ,       rs_ILLEGAL__ns_stay       , },
    [TTP_EV__TXQ__TTP_CLOSE]       = { _no_rs__no_ns_  ,       rs_ILLEGAL__ns_stay        ,       rs_CLOSE__ns_CLOSE_SENT  ,      rs_ILLEGAL__ns_stay    ,       rs_CLOSE__ns_CLOSE_SENT  ,         rs_none__ns_CLOSE_SENT ,          rs_none__ns_CLOSE_SENT , },
    [TTP_EV__TXQ__TTP_PAYLOAD]     = { _no_rs__no_ns_  ,         rs_STALL__ns_stay        ,       rs_STALL__ns_stay        ,        rs_STALL__ns_stay    ,     rs_PAYLOAD__ns_stay        ,     rs_PAYLOAD2__ns_stay       ,      rs_PAYLOAD2__ns_stay       , },
    [TTP_EV__TXQ__REPLAY_DATA]     = { _no_rs__no_ns_  ,          rs_OPEN__ns_OPEN_SENT   ,     rs_PAYLOAD__ns_stay        ,      rs_PAYLOAD__ns_stay    ,     rs_PAYLOAD__ns_stay        ,        rs_STALL__ns_stay       ,       rs_PAYLOAD__ns_stay       , },
    [TTP_EV__TXQ__REPLAY_CLOSE]    = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,       rs_CLOSE__ns_CLOSE_SENT  ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__RXQ__TTP_OPEN]        = { _no_rs__no_ns_  ,          rs_none__ns_OPEN_RECD   ,    rs_OPEN_ACK__ns_OPEN        ,     rs_OPEN_ACK__ns_stay ,    rs_OPEN_ACK__ns_stay        ,     rs_OPEN_ACK__ns_stay       ,      rs_OPEN_ACK__ns_stay       , },
    [TTP_EV__RXQ__TTP_OPEN_ACK]    = { _no_rs__no_ns_  ,       rs_ILLEGAL__ns_stay        ,        rs_none__ns_OPEN        ,         rs_none__ns_stay    ,        rs_none__ns_OPEN        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__RXQ__TTP_OPEN_NACK]   = { _no_rs__no_ns_  ,       rs_ILLEGAL__ns_stay        ,    rs_NOC_FAIL__ns_CLOSED      ,      rs_ILLEGAL__ns_stay    ,     rs_ILLEGAL__ns_stay        ,      rs_ILLEGAL__ns_stay       ,       rs_ILLEGAL__ns_stay       , },
    [TTP_EV__RXQ__TTP_CLOSE]       = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,         rs_none__ns_CLOSE_RECD  ,        rs_none__ns_CLOSE_RECD    ,          rs_none__ns_stay       , },
    [TTP_EV__RXQ__TTP_CLOSE_ACK]   = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,      rs_NOC_END__ns_CLOSED     ,          rs_none__ns_CLOSED     , },
    [TTP_EV__RXQ__TTP_CLOSE_NACK]  = { _no_rs__no_ns_  ,       rs_ILLEGAL__ns_stay        ,     rs_ILLEGAL__ns_stay        ,      rs_ILLEGAL__ns_stay    ,         rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__RXQ__TTP_PAYLOAD]     = { _no_rs__no_ns_  ,   rs_NACK_NOLINK__ns_stay        , rs_NACK_NOLINK__ns_stay        ,  rs_NACK_NOLINK__ns_stay    ,         rs_ACK__ns_stay        ,          rs_ACK__ns_stay       ,           rs_ACK__ns_stay       , },
    [TTP_EV__RXQ__TTP_ACK]         = { _no_rs__no_ns_  ,          rs_DROP__ns_stay        ,        rs_DROP__ns_stay        ,         rs_DROP__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__RXQ__TTP_NACK]        = { _no_rs__no_ns_  ,          rs_DROP__ns_stay        ,        rs_DROP__ns_stay        ,         rs_DROP__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__RXQ__TTP_NACK_FULL]   = { _no_rs__no_ns_  ,          rs_DROP__ns_stay        ,        rs_DROP__ns_stay        ,         rs_DROP__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__RXQ__TTP_NACK_NOLINK] = { _no_rs__no_ns_  ,         rs_STALL__ns_stay        ,       rs_STALL__ns_stay        ,        rs_STALL__ns_stay    ,        rs_OPEN__ns_OPEN_SENT   ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__RXQ__TTP_UNXP_PAYLD]  = { _no_rs__no_ns_  ,   rs_NACK_NOLINK__ns_stay        ,        rs_none__ns_stay        ,         rs_NACK__ns_stay    ,        rs_NACK__ns_stay        ,         rs_NACK__ns_stay       ,       rs_ILLEGAL__ns_stay       , },
    [TTP_EV__AKQ__OPEN_ACK]        = { _no_rs__no_ns_  ,          rs_DROP__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__AKQ__OPEN_NACK]       = { _no_rs__no_ns_  ,     rs_OPEN_NACK__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__AKQ__CLOSE_ACK]       = { _no_rs__no_ns_  ,     rs_CLOSE_ACK__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__AKQ__CLOSE_NACK]      = { _no_rs__no_ns_  ,          rs_DROP__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__AKQ__ACK]             = { _no_rs__no_ns_  ,          rs_DROP__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__AKQ__NACK]            = { _no_rs__no_ns_  ,          rs_DROP__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__INQ__TIMEOUT]         = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_OPEN__ns_OPEN_SENT   ,         rs_none__ns_stay    , rs_REPLAY_DATA__ns_stay        ,        rs_CLOSE__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__INQ__VICTIM]          = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,       rs_CLOSE__ns_CLOSE_SENT  ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__INQ__FOUND_WAY]       = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_OPEN__ns_OPEN_SENT   ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__INQ__NO_WAY]          = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,       rs_CLOSE__ns_CLOSED      ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__INQ__ALLOC_TAG]       = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_none__ns_stay        ,     rs_OPEN_ACK__ns_OPEN    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__INQ__NO_TAG]          = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_none__ns_stay        ,    rs_OPEN_NACK__ns_CLOSED  ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,          rs_none__ns_stay       , },
    [TTP_EV__INQ__YES_QUIESCED]    = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,     rs_CLOSE_ACK__ns_CLOSED     , },
    [TTP_EV__INQ__NOT_QUIESCED]    = { _no_rs__no_ns_  ,          rs_none__ns_stay        ,        rs_none__ns_stay        ,         rs_none__ns_stay    ,        rs_none__ns_stay        ,         rs_none__ns_stay       ,         rs_none__ns_stay       , },
};
