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

#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/crc16.h>
#include <net/addrconf.h>
#include <net/ip.h>

#include <ttp.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "print.h"
#include "noc.h"
#include "socket.h"


struct ttp_link_tag_global ttp_global_root_head;

struct ttp_link_tag  ttp_link_tag_tbl_0[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];
struct ttp_link_tag  ttp_link_tag_tbl_1[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];
struct ttp_link_tag  ttp_link_tag_tbl_2[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];
static struct ttp_rx_ooo_entry ttp_rx_ooo_tbl_0[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM][TTP_RX_OOO_SIZE];
static struct ttp_rx_ooo_entry ttp_rx_ooo_tbl_1[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM][TTP_RX_OOO_SIZE];
static struct ttp_rx_ooo_entry ttp_rx_ooo_tbl_2[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM][TTP_RX_OOO_SIZE];

struct ttp_stats_all ttp_stats;
static atomic_t ttp_epoch_next = ATOMIC_INIT (0);

int ttp_tag_seq_init_val = 1; /* can be any value (try: test with other values) */
int ttp_evlog_enabled = 1;

static inline void ttp_tag_touch (struct ttp_link_tag *lt)
{
    if (lt && lt->valid) {
        WRITE_ONCE (lt->last_used, jiffies);
    }
}

static u16 ttp_epoch_alloc (void)
{
    u16 epoch = (u16)atomic_inc_return (&ttp_epoch_next);

    if (!epoch) {
        epoch = (u16)atomic_inc_return (&ttp_epoch_next);
    }

    return epoch;
}

void ttp_tag_note_peer_epoch (struct ttp_link_tag *lt, u16 epoch)
{
    if (!lt || !lt->rx_ooo) {
        return;
    }

    lt->peer_epoch = epoch;
    lt->peer_epoch_valid = true;
}

TTP_NOTRACE
static u8 ttp_tag_index_hash_get (u64 kid)
{
    struct ttp_link_tag lt;

    lt._rkid = kid;
    return lt.hvl;
}


TTP_NOTRACE
static u8 ttp_tag_index_vci_get (u64 kid)
{
    struct ttp_link_tag lt;

    lt._rkid = kid;
    return lt.vci;
}


TTP_NOTRACE
static u8 ttp_tag_index_gwf_get (u64 kid)
{
    struct ttp_link_tag lt;

    lt._rkid = kid;
    return lt.gwf;
}


TTP_NOTRACE
static u8 ttp_tag_index_tip_get (u64 kid)
{
    struct ttp_link_tag lt;

    lt._rkid = kid;
    return lt.tip;
}


/*
 * Init sw-link-tag with a fully-associative raw 64b kid. This indexes a globally unique
 * ttp end-point. The u8 hash-value is also stored. The 256-entry 2-way hash-table is a
 * cache for the fully-associative sw-link-tag table. The tag is 'invalid' at init.
 */
u64 ttp_tag_key_make (const u8 *mac, u8 vc, bool gw, bool t3)
{
    struct ttp_link_tag lt;

    lt._rkid = 0ULL;            /* clear just the raw tag bits */

    if (!mac || !TTP_VC_ID__IS_VALID (vc)) {
        return lt._rkid;        /* 0ULL tag (kid) is invalid */
    }

    lt.hvl = ttp_tag_index_hash_calc (mac);

    lt.vci = vc;
    lt.gwf = gw;
    lt.tip = t3;

    lt.mac[0] = mac[3];
    lt.mac[1] = mac[4];
    lt.mac[2] = mac[5];

    lt.bkt = 0;

    lt.rng = 0;
    lt.oct = 0;

    return lt._rkid;
}


TTP_NOINLINE
static void ttp_tag_signal_tag (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag *lt;

    if (TTP_EV__TXQ__TTP_PAYLOAD != ev->evt) {
        return;
    }
    if ((lt = ttp_rbtree_tag_get (ev->kid)) && lt->txt) {
        lt->txt--;
    }
}


bool ttp_tag_has_pending_noc (struct ttp_link_tag *lt)
{
    bool pending = false;

    if (!lt) {
        return false;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);
    pending = !list_empty (&lt->ncq);
    mutex_unlock (&ttp_global_root_head.event_mutx);

    if (pending) {
        return true;
    }

    TTP_RUN_SPIN_LOCKED ({
        pending = !!(lt->tct || lt->txt);
    });

    return pending;
}

bool ttp_tag_is_quiesced (struct ttp_link_tag *lt)
{
    bool pending = false;

    if (!lt) {
        return false;
    }

    if (ttp_tag_has_pending_noc (lt)) {
        return false;
    }

    TTP_RUN_SPIN_LOCKED ({
        if (lt->tct || lt->txt) {
            pending = true;
        }
    });

    if (pending) {
        return false;
    }

    if (lt->full_blocked || lt->close_blocked) {
        return false;
    }

    return true;
}

static void ttp_tag_maybe_signal_quiesced (struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *ev;

    if (!lt || lt->state != TTP_ST__CLOSE_RECD) {
        return;
    }
    if (!lt->close_ack_pending || lt->close_ack_sent) {
        return;
    }
    if (!ttp_tag_is_quiesced (lt)) {
        return;
    }
    if (!ttp_evt_pget (&ev)) {
        return;
    }

    ev->evt = TTP_EV__INQ__YES_QUIESCED;
    ev->kid = lt->_rkid;
    ttp_evt_enqu (ev);
}


void ttp_tag_mark_orphaned (struct ttp_link_tag *lt)
{
    if (!lt) {
        return;
    }

    TTP_RUN_SPIN_LOCKED ({
        lt->sock_orphaned = true;
    });
}


void ttp_tag_maybe_cleanup_orphan (struct ttp_link_tag *lt)
{
    int tv;
    bool should_reset = false;
    bool queue_empty = false;

    if (!lt) {
        return;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);
    queue_empty = list_empty (&lt->ncq);
    mutex_unlock (&ttp_global_root_head.event_mutx);

    TTP_RUN_SPIN_LOCKED ({
        should_reset = lt->sock_orphaned && !lt->sock && !lt->tct && !lt->txt;
    });

    if (queue_empty && should_reset) {
        if (timer_pending (&lt->tmr)) {
            tv = del_timer (&lt->tmr);
            (void)tv;
        }
        ttp_tag_reset (lt);
    }
}

static void ttp_rx_ooo_flush_locked (struct ttp_link_tag *lt)
{
    int i;

    if (!lt) {
        return;
    }

    for (i = 0; i < TTP_RX_OOO_SIZE; i++) {
        if (lt->rx_ooo[i].skb) {
            ttp_skb_drop (lt->rx_ooo[i].skb);
        }
        lt->rx_ooo[i].skb = NULL;
        lt->rx_ooo[i].valid = false;
        lt->rx_ooo[i].seq = 0;
        lt->rx_ooo[i].noc_len = 0;
    }
}

void ttp_rx_ooo_flush (struct ttp_link_tag *lt)
{
    mutex_lock (&ttp_global_root_head.event_mutx);
    ttp_rx_ooo_flush_locked (lt);
    mutex_unlock (&ttp_global_root_head.event_mutx);
}

bool ttp_rx_ooo_store (struct ttp_link_tag *lt, u32 seq,
                       struct sk_buff *skb, u16 noc_len)
{
    u32 expected;
    u32 last;
    u32 slot;
    struct sk_buff *copy;
    bool stored = false;

    if (!lt || !lt->rx_ooo || !skb || !seq) {
        return false;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    expected = ttp_seq_next_u32 (lt->rx_seq_id);
    last = expected + TTP_RX_OOO_SIZE;
    if (!ttp_seq_after_u32 (seq, expected) || ttp_seq_after_u32 (seq, last)) {
        goto out_unlock;
    }

    slot = seq & (TTP_RX_OOO_SIZE - 1);
    if (lt->rx_ooo[slot].valid && lt->rx_ooo[slot].seq == seq) {
        stored = true;
        goto out_unlock;
    }
    if (lt->rx_ooo[slot].valid) {
        atomic_inc (&ttp_stats.rx_sack_dropped);
        goto out_unlock;
    }

    copy = skb_clone (skb, GFP_ATOMIC);
    if (!copy) {
        atomic_inc (&ttp_stats.rx_sack_dropped);
        goto out_unlock;
    }

    lt->rx_ooo[slot].valid = true;
    lt->rx_ooo[slot].seq = seq;
    lt->rx_ooo[slot].noc_len = noc_len;
    lt->rx_ooo[slot].skb = copy;
    stored = true;
    atomic_inc (&ttp_stats.rx_sack_cached);

out_unlock:
    mutex_unlock (&ttp_global_root_head.event_mutx);
    return stored;
}

bool ttp_rx_ooo_take (struct ttp_link_tag *lt, u32 seq,
                      struct sk_buff **skb, u16 *noc_len)
{
    u32 slot;
    bool found = false;

    if (!lt || !lt->rx_ooo || !skb || !noc_len) {
        return false;
    }

    *skb = NULL;
    *noc_len = 0;

    mutex_lock (&ttp_global_root_head.event_mutx);

    slot = seq & (TTP_RX_OOO_SIZE - 1);
    if (lt->rx_ooo[slot].valid && lt->rx_ooo[slot].seq == seq) {
        *skb = lt->rx_ooo[slot].skb;
        *noc_len = lt->rx_ooo[slot].noc_len;
        lt->rx_ooo[slot].skb = NULL;
        lt->rx_ooo[slot].valid = false;
        lt->rx_ooo[slot].seq = 0;
        lt->rx_ooo[slot].noc_len = 0;
        found = true;
    }

    mutex_unlock (&ttp_global_root_head.event_mutx);
    return found;
}

u64 ttp_rx_ooo_bitmap (struct ttp_link_tag *lt, u32 base)
{
    int i;
    u32 off;
    u64 bitmap = 0;

    if (!lt || !lt->rx_ooo || !base) {
        return 0;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    for (i = 0; i < TTP_RX_OOO_SIZE; i++) {
        if (!lt->rx_ooo[i].valid) {
            continue;
        }
        if (ttp_seq_before_u32 (lt->rx_ooo[i].seq, base)) {
            continue;
        }
        off = lt->rx_ooo[i].seq - base;
        if (off < 64) {
            bitmap |= BIT_ULL (off);
        }
    }

    mutex_unlock (&ttp_global_root_head.event_mutx);
    return bitmap;
}

static inline bool ttp_noc_evt_is_sent (const struct ttp_fsm_event *ev)
{
    return !!(ev->tx_flags & TTP_NOC_TXF_SENT);
}

static inline bool ttp_noc_evt_is_acked (const struct ttp_fsm_event *ev)
{
    return !!(ev->tx_flags & TTP_NOC_TXF_ACKED);
}

static inline bool ttp_noc_evt_is_retrans (const struct ttp_fsm_event *ev)
{
    return !!(ev->tx_flags & TTP_NOC_TXF_RETRANS);
}

static struct ttp_fsm_event *ttp_noc_first_unacked_locked (struct ttp_link_tag *lt);

static bool ttp_noc_close_replay_ready_locked (struct ttp_link_tag *lt)
{
    if (!lt->close_blocked) {
        return true;
    }

    if (!lt->close_tx_id) {
        return true;
    }

    if (lt->close_nack_rx_id && ttp_seq_before_u32 (lt->retire_id, lt->close_nack_rx_id)) {
        return false;
    }

    if (ttp_seq_geq_u32 (ttp_seq_next_u32 (lt->retire_id), lt->close_tx_id)) {
        return true;
    }

    if (!ttp_noc_first_unacked_locked (lt)) {
        return true;
    }

    return false;
}

static struct ttp_fsm_event *ttp_noc_find_seq_locked (struct ttp_link_tag *lt, u32 seq)
{
    struct ttp_fsm_event *ev;

    list_for_each_entry (ev, &lt->ncq, elm) {
        if (ev->psi.txi_seq == seq) {
            return ev;
        }
    }

    return NULL;
}

static bool ttp_noc_duplicate_nack_allows_retry_locked (struct ttp_link_tag *lt, u32 seq)
{
    struct ttp_fsm_event *ev;

    if (!lt->nack_recovery_active) {
        return true;
    }

    if (ttp_seq_before_u32 (seq, lt->nack_recovery_seq)) {
        lt->nack_dup_count = 0;
        return true;
    }

    if (ttp_seq_after_u32 (seq, lt->nack_recovery_seq)) {
        atomic_inc (&ttp_stats.duplicate_nack_ignored);
        return false;
    }

    ev = ttp_noc_find_seq_locked (lt, seq);
    if (ev && ttp_noc_evt_is_retrans (ev)) {
        atomic_inc (&ttp_stats.duplicate_nack_ignored);
        return false;
    }

    if (time_before (jiffies, lt->nack_recovery_jiffies +
                     msecs_to_jiffies (TTP_DUP_NACK_RETRY_MS))) {
        atomic_inc (&ttp_stats.duplicate_nack_ignored);
        return false;
    }

    lt->nack_dup_count++;
    if (lt->nack_dup_count < TTP_DUP_NACK_FAST_RETRY) {
        atomic_inc (&ttp_stats.duplicate_nack_ignored);
        return false;
    }

    /*
     * The first recovery attempt may itself be lost.  After a small duplicate
     * NACK threshold, allow one more fast retransmit instead of waiting for the
     * much slower payload timeout.
     */
    lt->nack_dup_count = 0;
    lt->nack_recovery_active = false;
    return true;
}

static struct ttp_fsm_event *ttp_noc_first_unacked_locked (struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *ev;

    list_for_each_entry (ev, &lt->ncq, elm) {
        if (!ttp_noc_evt_is_acked (ev)) {
            return ev;
        }
    }

    return NULL;
}

static struct ttp_fsm_event *ttp_noc_first_unsent_locked (struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *ev;

    list_for_each_entry (ev, &lt->ncq, elm) {
        if (!ttp_noc_evt_is_acked (ev) && !ttp_noc_evt_is_sent (ev)) {
            return ev;
        }
    }

    return NULL;
}

static struct ttp_fsm_event *ttp_noc_first_retrans_locked (struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *ev;

    list_for_each_entry (ev, &lt->ncq, elm) {
        if (ttp_noc_evt_is_acked (ev) || !ttp_noc_evt_is_sent (ev) || !ttp_noc_evt_is_retrans (ev)) {
            continue;
        }
        if (!lt->retransmit_from || ttp_seq_geq_u32 (ev->psi.txi_seq, lt->retransmit_from)) {
            return ev;
        }
    }

    return NULL;
}

static u16 ttp_noc_inflight_locked (struct ttp_link_tag *lt)
{
    return lt ? lt->inflight : 0;
}

static u16 ttp_noc_effective_window_locked (struct ttp_link_tag *lt)
{
    u16 cwnd;

    if (!lt) {
        return 1;
    }

    cwnd = lt->cwnd ? lt->cwnd : lt->twz;
    return clamp_t (u16, cwnd, 1, lt->twz);
}

static void ttp_noc_cwnd_loss_locked (struct ttp_link_tag *lt)
{
    u16 target;

    if (!lt) {
        return;
    }

    target = min_t (u16, lt->twz, TTP_CWND_LOSS_TARGET);
    target = max_t (u16, target, 1);
    if (!lt->cwnd || lt->cwnd > target) {
        lt->cwnd = target;
    }
    lt->cwnd_acked = 0;
    lt->cwnd_loss_seen = true;
}

static void ttp_noc_cwnd_ack_locked (struct ttp_link_tag *lt, u16 acked)
{
    u16 cwnd;
    u16 step;
    u32 threshold;

    if (!lt || !acked || lt->cwnd >= lt->twz) {
        return;
    }

    lt->cwnd_acked += acked;
    cwnd = ttp_noc_effective_window_locked (lt);
    if (lt->cwnd_loss_seen) {
        step = TTP_CWND_LOSS_GROW_STEP;
        threshold = (u32)cwnd * TTP_CWND_LOSS_GROW_DIV;
    }
    else {
        step = TTP_CWND_GROW_STEP;
        threshold = cwnd;
    }
    threshold = max_t (u32, threshold, 1);

    while (lt->cwnd_acked >= threshold && lt->cwnd < lt->twz) {
        lt->cwnd_acked -= threshold;
        lt->cwnd = min_t (u16, lt->twz, lt->cwnd + step);
        cwnd = ttp_noc_effective_window_locked (lt);
        threshold = lt->cwnd_loss_seen ? (u32)cwnd * TTP_CWND_LOSS_GROW_DIV : cwnd;
        threshold = max_t (u32, threshold, 1);
    }
}

static void ttp_noc_refresh_window_locked (struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *ev;

    ev = ttp_noc_first_unacked_locked (lt);
    if (!ev) {
        lt->base_seq = lt->tx_seq_id;
        lt->next_seq = lt->tx_seq_id;
        lt->retransmit_from = 0;
        lt->nack_recovery_seq = 0;
        lt->nack_recovery_active = false;
        lt->nack_dup_count = 0;
        lt->nack_recovery_jiffies = 0;
        return;
    }

    lt->base_seq = ev->psi.txi_seq;
    lt->next_seq = lt->tx_seq_id;

    if (lt->nack_recovery_active &&
        ttp_seq_before_u32 (lt->nack_recovery_seq, lt->base_seq)) {
        lt->nack_recovery_seq = 0;
        lt->nack_recovery_active = false;
        lt->nack_dup_count = 0;
        lt->nack_recovery_jiffies = 0;
    }

    if (lt->retransmit_from && ttp_seq_before_u32 (lt->retransmit_from, lt->base_seq)) {
        lt->retransmit_from = lt->base_seq;
    }
    if (lt->retransmit_from && !ttp_noc_first_retrans_locked (lt)) {
        lt->retransmit_from = 0;
    }
}

bool ttp_noc_ack_seq (struct ttp_link_tag *lt, u32 ack_seq, bool *advanced)
{
    LIST_HEAD (retired);
    bool matched = false;
    bool moved = false;
    u32 old_base = 0;
    u16 retired_count = 0;
    struct ttp_fsm_event *ev, *tmp;

    if (advanced) {
        *advanced = false;
    }
    if (!lt) {
        return false;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    old_base = lt->base_seq;
    if (ack_seq && ttp_seq_before_u32 (ack_seq, lt->base_seq)) {
        matched = true;
        goto out_unlock;
    }

    if (!ttp_noc_find_seq_locked (lt, ack_seq)) {
        goto out_unlock;
    }
    matched = true;

    list_for_each_entry (ev, &lt->ncq, elm) {
        if (ttp_seq_after_u32 (ev->psi.txi_seq, ack_seq)) {
            break;
        }
        if (ttp_noc_evt_is_sent (ev) && !ttp_noc_evt_is_acked (ev)) {
            ev->tx_flags |= TTP_NOC_TXF_ACKED;
            matched = true;
        }
    }

    list_for_each_entry_safe (ev, tmp, &lt->ncq, elm) {
        if (!ttp_noc_evt_is_acked (ev)) {
            break;
        }
        TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_FREE, TTP_OP__TTP_ACK);
        list_del (&ev->elm);
        list_add_tail (&ev->elm, &retired);
        lt->retire_id = ev->psi.txi_seq;
        lt->tct--;
        if (lt->inflight && ttp_noc_evt_is_sent (ev)) {
            lt->inflight--;
        }
        ttp_stats.nocq--;
        moved = true;
        retired_count++;
    }

    ttp_noc_refresh_window_locked (lt);
    if (moved && lt->base_seq != old_base) {
        lt->try = 0;
        lt->full_blocked = false;
        lt->full_backoff_active = false;
        lt->full_retry = 0;
        lt->local_congestion = 0;
        ttp_noc_cwnd_ack_locked (lt, retired_count);
    }
    if (ttp_noc_close_replay_ready_locked (lt)) {
        lt->close_blocked = false;
        lt->close_nack_rx_id = 0;
    }

out_unlock:
    mutex_unlock (&ttp_global_root_head.event_mutx);

    list_for_each_entry_safe (ev, tmp, &retired, elm) {
        list_del (&ev->elm);
        ttp_evt_pput (ev);
    }

    if (advanced) {
        *advanced = moved;
    }

    if (moved) {
        ttp_tag_maybe_signal_quiesced (lt);
        ttp_tag_maybe_cleanup_orphan (lt);
    }

    return matched;
}

bool ttp_noc_mark_retransmit_one (struct ttp_link_tag *lt, u32 seq)
{
    bool marked = false;
    struct ttp_fsm_event *ev;

    if (!lt || !seq) {
        return false;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_noc_refresh_window_locked (lt);
    if (!seq || ttp_seq_before_u32 (seq, lt->base_seq)) {
        seq = lt->base_seq;
    }

    ev = ttp_noc_find_seq_locked (lt, seq);
    if (ev && !ttp_noc_evt_is_acked (ev) && ttp_noc_evt_is_sent (ev)) {
        ev->tx_flags |= TTP_NOC_TXF_RETRANS;
        lt->retransmit_from = seq;
        marked = true;
    }

    mutex_unlock (&ttp_global_root_head.event_mutx);
    return marked;
}

bool ttp_noc_mark_retransmit_from (struct ttp_link_tag *lt, u32 seq)
{
    bool marked = false;
    struct ttp_fsm_event *ev;

    if (!lt || !seq) {
        return false;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_noc_refresh_window_locked (lt);
    if (ttp_seq_before_u32 (seq, lt->base_seq)) {
        atomic_inc (&ttp_stats.stale_nack_ignored);
        goto out_unlock;
    }
    if (!ttp_noc_duplicate_nack_allows_retry_locked (lt, seq)) {
        goto out_unlock;
    }

    ev = ttp_noc_find_seq_locked (lt, seq);
    if (ev && !ttp_noc_evt_is_acked (ev) && ttp_noc_evt_is_sent (ev)) {
        ev->tx_flags |= TTP_NOC_TXF_RETRANS;
        marked = true;
    }

    if (marked && (!lt->retransmit_from || ttp_seq_before_u32 (seq, lt->retransmit_from))) {
        lt->retransmit_from = seq;
    }
    if (marked) {
        lt->nack_recovery_seq = seq;
        lt->nack_recovery_active = true;
        lt->nack_dup_count = 0;
        lt->nack_recovery_jiffies = jiffies;
        ttp_noc_cwnd_loss_locked (lt);
    }

out_unlock:
    mutex_unlock (&ttp_global_root_head.event_mutx);
    return marked;
}

bool ttp_noc_mark_retransmit_sack (struct ttp_link_tag *lt, u32 seq,
                                   u32 sack_base, u64 sack_bitmap)
{
    bool marked = false;
    struct ttp_fsm_event *ev;
    u32 off;
    u32 sack_limit = 0;
    int bit;

    if (!lt || !seq) {
        return false;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_noc_refresh_window_locked (lt);
    if (ttp_seq_before_u32 (seq, lt->base_seq)) {
        atomic_inc (&ttp_stats.stale_nack_ignored);
        goto out_unlock;
    }
    if (!ttp_noc_duplicate_nack_allows_retry_locked (lt, seq)) {
        goto out_unlock;
    }

    /*
     * A SACK NACK says "seq is the first missing payload" and the bitmap only
     * proves which later payloads have already arrived.  Do not fall back to
     * Go-Back-N for payloads beyond the highest SACK bit; they may still be in
     * flight and retransmitting them is the main source of amplification.
     */
    for (bit = 63; bit >= 0; bit--) {
        if (sack_bitmap & BIT_ULL (bit)) {
            sack_limit = sack_base + bit;
            break;
        }
    }

    list_for_each_entry (ev, &lt->ncq, elm) {
        if (ttp_seq_before_u32 (ev->psi.txi_seq, seq)) {
            continue;
        }
        if (ttp_noc_evt_is_acked (ev) || !ttp_noc_evt_is_sent (ev)) {
            continue;
        }
        if (ev->psi.txi_seq != seq) {
            if (!sack_limit || ttp_seq_after_u32 (ev->psi.txi_seq, sack_limit)) {
                break;
            }
        }
        if (sack_base && ttp_seq_geq_u32 (ev->psi.txi_seq, sack_base)) {
            off = ev->psi.txi_seq - sack_base;
            if (off < 64 && (sack_bitmap & BIT_ULL (off))) {
                continue;
            }
        }
        ev->tx_flags |= TTP_NOC_TXF_RETRANS;
        if (!marked) {
            lt->retransmit_from = ev->psi.txi_seq;
        }
        marked = true;
    }

    if (marked) {
        lt->nack_recovery_seq = seq;
        lt->nack_recovery_active = true;
        lt->nack_dup_count = 0;
        lt->nack_recovery_jiffies = jiffies;
        ttp_noc_cwnd_loss_locked (lt);
    }

out_unlock:
    mutex_unlock (&ttp_global_root_head.event_mutx);
    return marked;
}

static unsigned int ttp_noc_full_backoff_ms (struct ttp_link_tag *lt)
{
    unsigned int shift;
    unsigned int delay;

    if (!lt) {
        return TTP_TMX_FULL_BASE_MS;
    }

    shift = min_t (unsigned int, lt->full_retry, 10);
    delay = TTP_TMX_FULL_BASE_MS << shift;
    return min_t (unsigned int, delay, TTP_TMX_FULL_MAX_MS);
}

void ttp_noc_start_full_backoff (struct ttp_link_tag *lt, struct ttp_fsm_event *qev)
{
    unsigned int delay;

    if (!lt) {
        return;
    }

    delay = ttp_noc_full_backoff_ms (lt);
    lt->full_backoff_active = true;

    if (timer_pending (&lt->tmr)) {
        mod_timer_pending (&lt->tmr, jiffies + msecs_to_jiffies (delay));
        TTP_EVLOG (qev, TTP_LG__LN_TIMER_RESTART, TTP_OP__TTP_NACK_FULL);
    }
    else {
        lt->tmr.expires = jiffies + msecs_to_jiffies (delay);
        add_timer (&lt->tmr);
        TTP_EVLOG (qev, TTP_LG__LN_TIMER_START, TTP_OP__TTP_NACK_FULL);
    }
}

void ttp_noc_mark_timeout (struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *ev;

    if (!lt) {
        return;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);
    ttp_noc_refresh_window_locked (lt);
    if (lt->base_seq && ttp_seq_before_u32 (lt->base_seq, lt->tx_seq_id)) {
        list_for_each_entry (ev, &lt->ncq, elm) {
            if (ttp_seq_before_u32 (ev->psi.txi_seq, lt->base_seq)) {
                continue;
            }
            if (ttp_noc_evt_is_acked (ev) || !ttp_noc_evt_is_sent (ev)) {
                continue;
            }
            ev->tx_flags |= TTP_NOC_TXF_RETRANS;
        }
        if (!lt->retransmit_from || ttp_seq_before_u32 (lt->base_seq, lt->retransmit_from)) {
            lt->retransmit_from = lt->base_seq;
        }
        lt->nack_recovery_seq = lt->base_seq;
        lt->nack_recovery_active = true;
        lt->nack_dup_count = 0;
        lt->nack_recovery_jiffies = jiffies;
        ttp_noc_cwnd_loss_locked (lt);
    }
    mutex_unlock (&ttp_global_root_head.event_mutx);
}


TTP_NOINLINE
static enum ttp_states_enum ttp_tag_get_state (u64 kid)
{
    struct ttp_link_tag *lt;

    if (kid && (lt = ttp_rbtree_tag_get (kid))) {
        return lt->state;
    }
    return TTP_ST__CLOSED;
}


TTP_NOINLINE
void ttp_tag_reset (struct ttp_link_tag *lt)
{
    struct ttp_sock *sock;
    u64 kid;

    sock = lt->sock;
    kid = lt->_rkid;

    if (kid) {
        atomic_inc (&ttp_stats.dels[lt->bkt]);
        ttp_rbtree_tag_del (kid);
    }
    ttp_rx_ooo_flush (lt);

    lt->valid       = 0;
    lt->state       = TTP_ST__CLOSED;
    lt->sock        = NULL;
    lt->sock_managed = false;
    lt->sock_orphaned = false;

    lt->retire_ptr  = 0;
    lt->current_ptr = 0;
    lt->alloc_ptr   = 0;

    lt->tx_seq_id   = 0;
    lt->rx_seq_id   = 0;
    lt->retire_id   = 0;
    lt->base_seq    = 0;
    lt->next_seq    = 0;
    lt->retransmit_from = 0;
    lt->nack_recovery_seq = 0;
    lt->nack_dup_count = 0;
    lt->nack_recovery_jiffies = 0;
    lt->close_tx_id = 0;
    lt->close_rx_id = 0;
    lt->close_nack_rx_id = 0;
    lt->peer_close_tx_id = 0;
    lt->local_epoch = 0;
    lt->peer_epoch = 0;
    lt->local_congestion = 0;
    lt->peer_congestion = 0;
    lt->rx_full_level = 0;
    lt->close_blocked = false;
    lt->nack_recovery_active = false;
    lt->cwnd_loss_seen = false;
    lt->full_blocked = false;
    lt->rx_full_blocked = false;
    lt->congestion_echo_pending = false;
    lt->close_ack_pending = false;
    lt->close_ack_sent = false;
    lt->open_tx_pending = false;
    lt->peer_epoch_valid = false;
    lt->last_used = 0;

    lt->tex = false;    /* timer expired */
    lt->twz = (u16)clamp_t (int, ttp_tx_window, 1, 512);
    lt->cwnd = min_t (u16, lt->twz, TTP_CWND_LOSS_TARGET);
    lt->cwnd = max_t (u16, lt->cwnd, 1);
    lt->cwnd_acked = 0;
    lt->inflight = 0;
    lt->tct = 0;        /* tx-queue count */
    lt->txt = 0;        /* tx-scheduled count */
    lt->try = 0;        /* tx-retry count */
    lt->full_retry = 0;
    lt->close_retry = 0;
    lt->full_backoff_active = false;

    lt->_rkid = 0ULL;   /* clear whole raw key id */
    RB_CLEAR_NODE (&lt->rbn);

    if (sock) {
        ttpoe_socket_tag_drop(sock, kid);
    }
}

void ttp_tag_force_reset(struct ttp_link_tag *lt)
{
    int dropped;

    if (!lt) {
        return;
    }

    del_timer_sync(&lt->tmr);
    /*
     * This reset path is also used from socket connect failure/timeout paths.
     * Do not synchronously wait for the tag work item here: repeated perf-test
     * setup/teardown can otherwise leave the caller stuck in cancel_work_sync().
     * Link tags are static table entries, so a late worker can safely observe
     * the reset CLOSED state instead of dereferencing freed memory.
     */
    cancel_work(&lt->wkq);

    dropped = lt->tct;
    while (ttp_noc_dequ(lt)) {
        ;
    }
    if (dropped) {
        if (ttp_stats.nocq >= dropped) {
            ttp_stats.nocq -= dropped;
        } else {
            ttp_stats.nocq = 0;
        }
    }

    ttp_tag_reset(lt);
}

static bool ttp_tag_victim_allowed (struct ttp_link_tag *lt)
{
    bool busy = false;

    if (!lt || !lt->valid) {
        return false;
    }

    TTP_RUN_SPIN_LOCKED ({
        busy = lt->sock || lt->sock_orphaned;
    });

    return !busy;
}

static struct ttp_link_tag *ttp_tag_lru_victim_get (struct ttp_link_tag *set)
{
    struct ttp_link_tag *lt, *victim = NULL;
    int bk;

    for (bk = 0; bk < TTP_TAG_TBL_BKTS_NUM; bk++) {
        lt = &set[bk];

        if (!ttp_tag_victim_allowed (lt)) {
            continue;
        }
        if (!victim ||
            time_before (READ_ONCE (lt->last_used), READ_ONCE (victim->last_used))) {
            victim = lt;
        }
    }

    return victim;
}

static bool ttp_tag_victimize_lru (struct ttp_link_tag *set)
{
    struct ttp_link_tag *victim;
    u64 old_kid;

    victim = ttp_tag_lru_victim_get (set);
    if (!victim) {
        atomic_inc (&ttp_stats.tag_victim_busy);
        return false;
    }

    old_kid = victim->_rkid;
    TTP_DB1 ("%s: evict lru tag 0x%016llx state:%u bkt:%u\n", __FUNCTION__,
             cpu_to_be64 (old_kid), victim->state, victim->bkt);

    ttp_tag_force_reset (victim);
    atomic_inc (&ttp_stats.tag_victims);

    return true;
}


/* add 'tag' to table: return 0 (hash val in kid); 1 if all bkts are full */
int ttp_tag_add (u64 kid)
{
    u8  vc, gw, hv, t3;
    int bk;
    struct ttp_link_tag *lt, *set;

    if ((lt = ttp_rbtree_tag_get (kid))) {
        ttp_tag_touch (lt);
        return 0;
    }

    hv = ttp_tag_index_hash_get (kid);
    vc = ttp_tag_index_vci_get (kid);
    gw = ttp_tag_index_gwf_get (kid);
    t3 = ttp_tag_index_tip_get (kid);

    if (vc == 0) {
        set = ttp_link_tag_tbl_0[hv];
    }
    else if (vc == 1) {
        set = ttp_link_tag_tbl_1[hv];
    }
    else if (vc == 2) {
        set = ttp_link_tag_tbl_2[hv];
    }
    else {
        BUG_ON (1);
    }

retry:
    lt = set;
    /* try bkt-0, then bkt-1, ... */
    for (bk = 0; bk < TTP_TAG_TBL_BKTS_NUM; bk++) {
        if (!lt->valid) { /* found an empty slot */
            lt->valid = 1;
            lt->state = TTP_ST__CLOSED;
            lt->sock = NULL;
            lt->sock_managed = false;
            lt->sock_orphaned = false;

            lt->_rkid = kid;
            ttp_rbtree_tag_add (lt);

            lt->bkt = bk;
            lt->gwf = gw;
            lt->tip = t3;
            lt->hvl = hv;
            lt->last_used = jiffies;

            lt->retire_id = ttp_tag_seq_init_val;
            lt->rx_seq_id = ttp_tag_seq_init_val;
            lt->tx_seq_id = ttp_tag_seq_init_val + 1; /* TTP_OPEN: init-val, use next */
            lt->local_epoch = ttp_epoch_alloc ();
            lt->peer_epoch = 0;
            lt->peer_epoch_valid = false;

            atomic_inc (&ttp_stats.adds[bk]);
            return 0;
        }

        lt++;  /* next bkt */
    }

    atomic_inc (&ttp_stats.coll[hv]);
    atomic_inc (&ttp_stats.colls);

    if (ttp_tag_victimize_lru (set)) {
        goto retry;
    }

    return 1; /* all ways full and no safe victim */
}


TTP_NOINLINE
static void ttp_fsm_lookup_state_table (u64 kid, enum ttp_events_enum evn,
                                        enum ttp_states_enum *cs,
                                        enum ttp_states_enum *ns,
                                        enum ttp_response_enum *rs)
{
    *cs = ttp_tag_get_state (kid);
    *ns = ttp_fsm_table[evn][*cs].next_state;
    *rs = ttp_fsm_table[evn][*cs].response;
}


TTP_NOINLINE
void ttp_fsm_evlog_add (const char *fil, const int lin,
                        const char *fun, const int pos,
                        struct ttp_fsm_event *qev, enum ttp_events_enum evn,
                        enum ttp_opcodes_enum opc, struct ttp_pkt_info *pif)
{
    struct ttp_link_tag *lt;
    struct ttp_fsm_evlog *lg;

    if (!READ_ONCE (ttp_evlog_enabled)) {
        return;
    }

    BUG_ON (qev && qev->tsk && qev->rsk);

    if (!mutex_trylock (&ttp_global_root_head.evlog_mutx)) {
        TTP_DBG ("%s: trylock failed, logev: %d\n", __FUNCTION__, evn);
        return;
    }

    lg = list_first_entry (&ttp_global_root_head.evlog_head, struct ttp_fsm_evlog, lm);
    if (!lg) {
        mutex_unlock (&ttp_global_root_head.evlog_mutx);
        return;
    }

    list_del (&lg->lm);

    lg->ps = pos;
    lg->ts = jiffies;
    lg->ev = evn;
    lg->op = opc;
    lg->kd = qev ? qev->kid : 0;
    lg->ix = qev ? qev->idx : 0;
    lg->rf = (qev && qev->tsk) ? refcount_read (&qev->tsk->users) : 0;

    lg->rx = lg->tx = -1;
    lg->sz = 0;
    if (pif) {
        if (!ttp_opcode_is_ack (opc)) {
            lg->rx = pif->rxi_seq;
            lg->tx = pif->txi_seq;
            if (TTP_OP__TTP_PAYLOAD == opc) {
                lg->sz = pif->noc_len;
            }
        }
        else {
            lg->rx = pif->rxi_seq;
        }
    }

    lg->fl = strstr (fil, "modttpoe");
    lg->fn = (u8 *)fun;
    lg->ln = lin;

    if (qev && qev->kid && TTP_EVENT_IS_VALID (lg->ev)) {
        ttp_fsm_lookup_state_table (lg->kd, lg->ev, &lg->cs, &lg->ns, &lg->rs);

        if ((lt = ttp_rbtree_tag_get (lg->kd))) {
            lg->vc = lt->vci;
            lg->hv = lt->hvl;
            lg->bk = lt->bkt;
        }
    }

    list_add_tail (&lg->lm, &ttp_global_root_head.evlog_head);
    ttp_stats.evlog++;

    mutex_unlock (&ttp_global_root_head.evlog_mutx);
}


DECLARE_BITMAP (ttp_bloom_bitmap, TTP_BLOOM_SIZE);

/* using reverse-bits */
TTP_NOTRACE
static u32 ttp_bloom_hash1 (u64 kid)
{
    u64 rv = 0;

    while (kid) {
        rv   ^= kid & TTP_BLOOM_MASK;
        kid >>= TTP_BLOOM_SIZE_BITS;
        kid   = (kid & 0xffffff00) | ttp_tag_reverse_bits (kid & 0xff);
    }

    rv = (rv & TTP_BLOOM_MASK) ^ ((rv >> TTP_BLOOM_SIZE_BITS) & TTP_BLOOM_MASK);
    return rv;
}


/* using crc16 */
TTP_NOTRACE
static u32 ttp_bloom_hash2 (u64 kid)
{
    u32 rv = 0;

    while (kid) {
        rv = crc16_byte (rv, kid & 0xff);
        kid >>= 8;
    }
    rv &= 0xffff;               /* crc16 */

    rv = (rv & TTP_BLOOM_MASK) ^ ((rv >> TTP_BLOOM_SIZE_BITS) & TTP_BLOOM_MASK);
    return rv;
}


/* using a FNV-like hash function */
TTP_NOTRACE
static u32 ttp_bloom_hash3 (u64 kid)
{
    u32 rv = 0;

    while (kid) {
        rv   *= 16777619;
        rv   ^= (kid & 0xff);
        kid >>= 8;
    }

    rv = (rv & TTP_BLOOM_MASK) ^ ((rv >> TTP_BLOOM_SIZE_BITS) & TTP_BLOOM_MASK);
    return rv;
}


TTP_NOTRACE
void ttp_bloom_add (u64 kid)
{
    set_bit (ttp_bloom_hash1 (kid), ttp_bloom_bitmap);
    set_bit (ttp_bloom_hash2 (kid), ttp_bloom_bitmap);
    set_bit (ttp_bloom_hash3 (kid), ttp_bloom_bitmap);
}


TTP_NOTRACE
int ttp_bloom_test (u64 kid)
{
    return test_bit (ttp_bloom_hash1 (kid), ttp_bloom_bitmap)
        && test_bit (ttp_bloom_hash2 (kid), ttp_bloom_bitmap);
}


/* returns -1 if t1->key < t2->key, 1 if '>', and 0 when equal */
static int ttp_rbtree_tag_key_cmp (struct ttp_link_tag *t1, struct ttp_link_tag *t2)
{
    u32 k1 = t1->_rkey, k2 = t2->_rkey;

    if (k1 < k2) {
        return -1;
    }
    else if (k1 > k2) {
        return 1;
    }
    else {
        return 0;
    }
}

TTP_NOINLINE
void ttp_rbtree_tag_add (struct ttp_link_tag *tag)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_link_tag *lt;
    int cmp;

    new = &ttp_global_root_head.tag_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lt = rb_entry (*new, struct ttp_link_tag, rbn);

        if ((cmp = ttp_rbtree_tag_key_cmp (lt, tag)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* keys are equal */
            return;
        }
    }

    rb_link_node (&tag->rbn, parent, new);
    rb_insert_color (&tag->rbn, &ttp_global_root_head.tag_rbroot);
}

TTP_NOINLINE
void ttp_rbtree_tag_del (u64 kid)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_link_tag *lt, tag = {0};
    int cmp;

    tag._rkid = kid;
    new = &ttp_global_root_head.tag_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lt = rb_entry (*new, struct ttp_link_tag, rbn);

        if ((cmp = ttp_rbtree_tag_key_cmp (lt, &tag)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* keys are equal */
            rb_erase (&lt->rbn, &ttp_global_root_head.tag_rbroot);
            RB_CLEAR_NODE (&lt->rbn);
            return;
        }
    }
}

TTP_NOINLINE
struct ttp_link_tag *ttp_rbtree_tag_get (u64 kid)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_link_tag *lt, tag = {0};
    int cmp;

    tag._rkid = kid;
    new = &ttp_global_root_head.tag_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lt = rb_entry (*new, struct ttp_link_tag, rbn);

        if ((cmp = ttp_rbtree_tag_key_cmp (lt, &tag)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* found it */
            ttp_tag_touch (lt);
            return lt;
        }
    }

    return NULL;
}


/* return 0 on failure to get pool event */
TTP_NOINLINE
static bool ttp_evt_pget_locked (struct ttp_fsm_event **evp)
{
    struct ttp_fsm_event *ev;

    if (!(ev = list_first_entry_or_null (&ttp_global_root_head.pool_head,
                                         struct ttp_fsm_event, elm))) {
        ttp_stats.ovr_fl++;
        return false;
    }
    BUG_ON (ev->rsk);
    BUG_ON (ev->tsk);

    ev->mrk = TTP_EVENTS_FENCE_FREE_ELEM;
    memset (&ev->psi, 0, sizeof (ev->psi));
    ev->tx_flags = 0;
    ev->fsm_override = 0;
    ev->fsm_response = 0;
    ev->fsm_next_state = 0;

    list_del (&ev->elm);
    ttp_stats.pool--;

    *evp = ev;
    return true;
}


/* return 0 on failure to get pool event */
bool ttp_evt_pget (struct ttp_fsm_event **evp)
{
    bool rv;

    mutex_lock (&ttp_global_root_head.event_mutx);

    rv = ttp_evt_pget_locked (evp);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    return rv;
}

TTP_NOINLINE
static void ttp_evt_pput_locked (struct ttp_fsm_event *ev)
{
    if (ev->rsk) {
        if (ev->mrk == TTP_EVENTS_FENCE_RX_Q_ELEM) {
            atomic_dec (&ttp_stats.skb_ct);
        }
        ttp_skb_drop (ev->rsk);
        ev->rsk = NULL;
    }

    if (ev->tsk) {
        ttp_skb_drop (ev->tsk);
        ev->tsk = NULL;
    }

    BUG_ON (ev->rsk);
    BUG_ON (ev->tsk);

    ev->kid = 0;
    ev->evt = TTP_EV__invalid;
    ev->mrk = TTP_EVENTS_FENCE_POOL_ELEM;
    memset (&ev->psi, 0, sizeof (ev->psi));
    ev->tx_flags = 0;
    ev->fsm_override = 0;
    ev->fsm_response = 0;
    ev->fsm_next_state = 0;

    list_add_tail (&ev->elm, &ttp_global_root_head.pool_head);
    ttp_stats.pool++;
}


void ttp_evt_pput (struct ttp_fsm_event *ev)
{
    if (!ev) {
        return;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_evt_pput_locked (ev);

    mutex_unlock (&ttp_global_root_head.event_mutx);
}

#define TTP_NUM_CHANNELS  4
#define TTP_WORK_DRAIN_BUDGET 64

TTP_NOINLINE
static int ttp_evt_getrr_locked (struct ttp_fsm_event **evp)
{
    static int rri = 0;
    int iv;
    struct list_head *qh;
    struct ttp_fsm_event *lev = NULL;
    struct list_head *qhs[TTP_NUM_CHANNELS] = { &ttp_global_root_head.rxq_head,
                                                &ttp_global_root_head.txq_head,
                                                &ttp_global_root_head.akq_head,
                                                &ttp_global_root_head.inq_head };

    for (iv = 0; iv < TTP_NUM_CHANNELS; iv++) {
        qh = qhs[rri];
        rri = (rri + 1) % TTP_NUM_CHANNELS;

        if ((lev = list_first_entry_or_null (qh, struct ttp_fsm_event, elm))) {
            *evp = lev;
            return rri;
        }
    }

    return -1;
}


TTP_UNUSED TTP_NOINLINE
static int ttp_evt_getsp_locked (struct ttp_fsm_event **evp)
{
    struct ttp_fsm_event *ev;

    if ((ev = list_first_entry_or_null (&ttp_global_root_head.rxq_head,
                                        struct ttp_fsm_event, elm))) {
        *evp = ev;
        return 0;
    }

    if ((ev = list_first_entry_or_null (&ttp_global_root_head.txq_head,
                                        struct ttp_fsm_event, elm))) {
        *evp = ev;
        return 1;
    }

    if ((ev = list_first_entry_or_null (&ttp_global_root_head.akq_head,
                                        struct ttp_fsm_event, elm))) {
        *evp = ev;
        return 2;
    }

    if ((ev = list_first_entry_or_null (&ttp_global_root_head.inq_head,
                                        struct ttp_fsm_event, elm))) {
        *evp = ev;
        return 3;
    }

    return -1;
}


TTP_NOINLINE
static int ttp_evt_dequ (void)
{
    int chnl;
    enum ttp_states_enum cs, ns;
    enum ttp_response_enum rs;
    struct ttp_fsm_event *ev;
    struct ttp_link_tag *lt;
    ttp_fsm_fn dqfnp;

    mutex_lock (&ttp_global_root_head.event_mutx);

    if ((chnl = ttp_evt_getrr_locked (&ev)) < 0) {
        mutex_unlock (&ttp_global_root_head.event_mutx);
        return 0;
    }

    list_del (&ev->elm);
    ttp_stats.queue--;

    mutex_unlock (&ttp_global_root_head.event_mutx);

    BUG_ON (ev->rsk && ev->tsk);

    /* ****************************** process event ****************************** */

    if (!TTP_EVENT_IS_VALID (ev->evt)) {
        TTP_EVLOG (ev, ev->evt, TTP_OP__invalid);
        goto end;
    }

    /* lookup fsm table */
    ttp_fsm_lookup_state_table (ev->kid, ev->evt, &cs, &ns, &rs);

    if (ttp_verbose_for_ctrl (ev->psi.noc_len)) {
        TTP_DBG ("##-> FSM Step: %s ==> %s / %s ==> %s\n",
                 TTP_STATE_NAME (cs), TTP_EVENT_NAME (ev->evt),
                 TTP_RESPONSE_NAME (rs), TTP_STATE_NAME (ns));
        TTP_DB1 ("`-> channel:%d 0x%016llx.%d rx:%d tx:%d\n", chnl,
                 cpu_to_be64 (ev->kid), ev->idx, ev->psi.rxi_seq, ev->psi.txi_seq);
    }

    TTP_EVLOG (ev, ev->evt, ttp_fsm_response_op[rs]);

    /* handle event */
    if ((lt = ttp_rbtree_tag_get (ev->kid))) {
        if (ttp_verbose_for_ctrl (ev->psi.noc_len)) {
            TTP_DB1 ("##`-> FSM Event-Handle: %s\n", TTP_EVENT_NAME (ev->evt));
            TTP_DB2 ("  `-> lt-rx:%d lt-tx:%d gw:%d tp:%d\n",
                     lt->rx_seq_id, lt->tx_seq_id, lt->gwf, lt->tip);
        }
    }
    dqfnp = ttp_fsm_event_handle_fn[ev->evt];
    if (dqfnp && ev->rsk) {
        if (!dqfnp (ev)) {
            TTP_DB1 ("!!`-> FSM Event-Handle: %s [FAILED]\n", TTP_EVENT_NAME (ev->evt));
        }
    }

    if (ev->fsm_override) {
        rs = ev->fsm_response;
        ns = ev->fsm_next_state;
        ev->fsm_override = 0;
    }

    /* do response */
    TTP_DB1 ("##`-> FSM Response: %s\n", TTP_RESPONSE_NAME (rs));
    dqfnp = ttp_fsm_response_fn[rs];
    if (dqfnp) {
        if (!dqfnp (ev)) {
            TTP_DBG ("!!`-> FSM Response: %s [FAILED]\n", TTP_RESPONSE_NAME (rs));
        }
    }

    ttp_tag_signal_tag (ev);

    ttpoe_socket_fsm_event (ev, rs, ns);

    /* call the state entry function for the state we're entering (ns) */
    TTP_DB1 ("##`-> FSM State-Entry: %s\n", TTP_STATE_NAME (ns));
    dqfnp = ttp_fsm_entry_function[ns];
    if (dqfnp) {
        if (!dqfnp (ev)) {
            TTP_DBG ("##`-> FSM State-Entry: %s [FAILED]\n", TTP_STATE_NAME (ns));
        }
    }

    if (lt) {
        schedule_work (&lt->wkq);
    }

    schedule_work (&ttp_global_root_head.work_queue); /* schedule work to drain queue */

    /* *************************** DONE process event *************************** */

end:
    ttp_evt_pput (ev);
    return 1;
}


TTP_NOINLINE
static void ttp_evt_enqu_locked (struct ttp_fsm_event *ev)
{
    switch (ev->evt) {
    case TTP_EV__RXQ__TTP_OPEN ... TTP_EV__RXQ__TTP_UNXP_PAYLD:
        ev->mrk = TTP_EVENTS_FENCE_RX_Q_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.rxq_head);
        break;

    case TTP_EV__TXQ__TTP_OPEN ... TTP_EV__TXQ__REPLAY_CLOSE:
        ev->mrk = TTP_EVENTS_FENCE_TX_Q_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.txq_head);
        break;

    case TTP_EV__AKQ__OPEN_ACK ... TTP_EV__AKQ__NACK:
        ev->mrk = TTP_EVENTS_FENCE_AK_Q_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.akq_head);
        break;

    case TTP_EV__INQ__TIMEOUT ... TTP_EV__INQ__NOT_QUIESCED:
        ev->mrk = TTP_EVENTS_FENCE_IN_Q_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.inq_head);
        break;

    default:
        ev->mrk = TTP_EVENTS_FENCE_EXPT_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.inq_head);
        break;
    }

    ttp_stats.queue++;
}


TTP_NOINLINE
static struct ttp_fsm_event *ttp_evt_cpqu_locked (const struct ttp_fsm_event *qev)
{
    struct ttp_fsm_event *ev;

    if (!ttp_evt_pget_locked (&ev)) {
        return NULL;
    }

    BUG_ON (ev->rsk);
    BUG_ON (ev->tsk);

    ev->evt = qev->evt;
    ev->kid = qev->kid;

    ttp_tsk_bind (ev, qev);

    ttp_evt_enqu_locked (ev);

    return ev;
}


int ttp_noc_dequ (struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *tev;

    mutex_lock (&ttp_global_root_head.event_mutx);

    tev = list_first_entry_or_null (&lt->ncq, struct ttp_fsm_event, elm);
    if (!tev) {
        mutex_unlock (&ttp_global_root_head.event_mutx);
        return 0;
    }

    list_del (&tev->elm);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    TTP_DB1 ("%s: 0x%016llx.%d evnt: %s\n", __FUNCTION__,
             cpu_to_be64 (tev->kid), tev->idx,
             TTP_EVENT_IS_VALID (tev->evt) ? TTP_EVENT_NAME (tev->evt) : "null");

    ttp_evt_pput (tev);

    return 1;
}


void ttp_noc_requ (struct ttp_link_tag *lt)
{
    static const int max_retry = 1000;
    struct ttp_fsm_event *ev, *tev;
    bool queued = false;
    bool fatal = false;
    u16 inflight = 0;
    u16 tx_limit;

    if (!lt) {
        return;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_noc_refresh_window_locked (lt);
    tev = ttp_noc_first_unacked_locked (lt);
    if (!tev) {
        mutex_unlock (&ttp_global_root_head.event_mutx);
        TTP_DB1 ("%s: 0x%016llx.%d\n", __FUNCTION__,
                 cpu_to_be64 (lt->_rkid), -1);
        return;
    }

    while (lt->txt < lt->twz) {
        ttp_noc_refresh_window_locked (lt);
        if (ttp_noc_close_replay_ready_locked (lt)) {
            lt->close_blocked = false;
            lt->close_nack_rx_id = 0;
        }
        if (lt->full_blocked) {
            tev = ttp_noc_find_seq_locked (lt, lt->base_seq);
            if (!tev || !ttp_noc_evt_is_sent (tev) || ttp_noc_evt_is_acked (tev) ||
                !ttp_noc_evt_is_retrans (tev)) {
                break;
            }
        }
        else {
            tev = ttp_noc_first_retrans_locked (lt);
        }
        if (tev) {
            if (tev->psi.txi_seq == lt->base_seq && lt->try >= max_retry) {
                fatal = true;
                break;
            }
            tev->tx_flags &= ~TTP_NOC_TXF_RETRANS;
            lt->txt++;
            atomic_inc (&ttp_stats.tx_retrans_pkts);
            atomic64_add (tev->psi.noc_len, &ttp_stats.tx_retrans_bytes);
            if (tev->psi.txi_seq == lt->base_seq) {
                lt->try++;
            }
            if (!ttp_fsm_tx_payload_direct (tev)) {
                ev = ttp_evt_cpqu_locked (tev);
                if (!ev) {
                    lt->txt--;
                    break;
                }
                queued = true;
            }
            else {
                ev = tev;
                if (lt->txt) {
                    lt->txt--;
                }
            }
            TTP_DB1 ("%s: `-> re-enqueue#%d %s len:%d tx:%d mark:%s\n", __FUNCTION__,
                     lt->try, TTP_EVENT_NAME (tev->evt), ev->psi.noc_len, ev->psi.txi_seq,
                     TTP_EVENTS_FENCE_TO_STR (tev->mrk));
            TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_REQ, TTP_OP__TTP_PAYLOAD);
            if (lt->full_blocked) {
                break;
            }
            continue;
        }

        tx_limit = ttp_noc_effective_window_locked (lt);
        inflight = ttp_noc_inflight_locked (lt);
        if (inflight >= tx_limit) {
            break;
        }
        if (lt->full_blocked) {
            break;
        }

        tev = ttp_noc_first_unsent_locked (lt);
        if (!tev) {
            break;
        }

        tev->tx_flags |= TTP_NOC_TXF_SENT;
        lt->inflight++;
        lt->txt++;
        if (!ttp_fsm_tx_payload_direct (tev)) {
            ev = ttp_evt_cpqu_locked (tev);
            if (!ev) {
                tev->tx_flags &= ~TTP_NOC_TXF_SENT;
                if (lt->inflight) {
                    lt->inflight--;
                }
                lt->txt--;
                break;
            }
            queued = true;
        }
        else {
            ev = tev;
            if (lt->txt) {
                lt->txt--;
            }
        }
        TTP_DB1 ("%s: `-> enqueue %s len:%d tx:%d mark:%s\n", __FUNCTION__,
                 TTP_EVENT_NAME (tev->evt), ev->psi.noc_len, ev->psi.txi_seq,
                 TTP_EVENTS_FENCE_TO_STR (tev->mrk));
    }
    mutex_unlock (&ttp_global_root_head.event_mutx);

    if (fatal) {
        int dropped = lt->tct;

        TTP_DB1 ("%s: 0x%016llx >max re-tries(%d) base:%u\n", __FUNCTION__,
                 cpu_to_be64 (lt->_rkid), max_retry, lt->base_seq);
        ttpoe_socket_link_error (lt->_rkid, ETIMEDOUT);
        if (timer_pending (&lt->tmr)) {
            del_timer (&lt->tmr);
        }
        while (ttp_noc_dequ (lt)) {
            ;
        }
        ttp_stats.nocq -= dropped;
        ttp_tag_reset (lt);
        return;
    }

    if (queued) {
        schedule_work (&lt->wkq);
    }

    ttp_tag_maybe_signal_quiesced (lt);
}


TTP_NOINLINE
static void ttp_do_global_work (struct work_struct *wk)
{
    int budget = TTP_WORK_DRAIN_BUDGET;
    int rv;

    if (0 == ttp_stats.wkq_sz) {
        ; /* fall thro' */
    }
    else if (0 == ttp_stats.wkq_st) {
        return;
    }
    else {
        ttp_stats.wkq_st--;
        budget = 1;
    }

    do {
        rv = 0;
        rv += ttp_evt_dequ ();
        rv += ttp_skb_dequ ();
    } while (rv && --budget);
}


TTP_NOINLINE
static void ttp_do_tag_work (struct work_struct *wk)
{
    int budget = TTP_WORK_DRAIN_BUDGET;
    int rv;
    bool do_tex = false;
    struct ttp_link_tag *lt;
    struct ttp_fsm_event *ev;

    if (0 == ttp_stats.wkq_sz) {
        ; /* fall thro' */
    }
    else if (0 == ttp_stats.wkq_st) {
        return;
    }
    else {
        ttp_stats.wkq_st--;
        budget = 1;
    }

    if (!(lt = from_work (lt, wk, wkq))) {
        return;
    }

    TTP_RUN_SPIN_LOCKED ({
        if (lt->tex) {
            lt->tex = false;
            do_tex = true;
        }
    });

    if (do_tex) {
        if (lt->full_backoff_active) {
            lt->full_backoff_active = false;
            atomic_inc (&ttp_stats.full_backoff_timeouts);
            ttp_noc_requ (lt);
            return;
        }
        if (ttp_evt_pget (&ev)) {
            ev->evt = TTP_EV__INQ__TIMEOUT;
            ev->kid = lt->_rkid;
            ttp_evt_enqu (ev);
            atomic_inc (&ttp_stats.payload_timeouts);
            TTP_DB1 ("%s: wq: evnt: int__TIMEOUT\n", __FUNCTION__);
            TTP_EVLOG (ev, TTP_LG__TIMER_TIMEOUT, TTP_OP__invalid);
        }
    }

    do {
        rv = ttp_evt_dequ ();
    } while (rv && --budget);
}


TTP_NOINLINE
static void ttp_fsm_tag_timer_callback (struct timer_list *tl)
{
    struct ttp_link_tag *lt;

    if (!(lt = from_timer (lt, tl, tmr))) {
        return;
    }

    /* signal that timer expired */
    lt->tex = true;

    schedule_work (&lt->wkq);
}


TTP_NOINLINE
static void ttp_fsm_global_timer_callback (struct timer_list *tl)
{
    /* placeholder for any global periodic work */
}


void ttp_evt_cpqu (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag  *lt;

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_evt_cpqu_locked (ev);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    if ((lt = ttp_rbtree_tag_get (ev->kid))) {
        schedule_work (&lt->wkq);
    }
    else {
        schedule_work (&ttp_global_root_head.work_queue);
    }
}


void ttp_evt_enqu (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag  *lt;

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_evt_enqu_locked (ev);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    if ((lt = ttp_rbtree_tag_get (ev->kid))) {
        schedule_work (&lt->wkq);
    }
    else {
        schedule_work (&ttp_global_root_head.work_queue);
    }

    TTP_DB1 ("%s: enqueue %s len:%d tx:%d mark:%s\n", __FUNCTION__,
             TTP_EVENT_NAME (ev->evt), ev->psi.noc_len, ev->psi.txi_seq,
             TTP_EVENTS_FENCE_TO_STR (ev->mrk));
}


static void ttp_noc_enqu_common (struct ttp_fsm_event *ev, bool kick)
{
    struct ttp_link_tag  *lt;

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        ttp_evt_pput (ev);
        return;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    /*
     * Publish the event to ncq only after assigning its sequence and updating
     * counters. Otherwise ACK retirement can observe a half-initialized tail
     * entry when the fast path is not slowed down by debug/evlog work.
     */
    TTP_RUN_SPIN_LOCKED ({
        ev->psi.txi_seq = lt->tx_seq_id;
        lt->tct++;
        lt->tx_seq_id++;
        lt->next_seq = lt->tx_seq_id;
        ttp_stats.nocq++;
    });

    list_add_tail (&ev->elm, &lt->ncq);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    if (kick) {
        /*
         * Enqueueing into nocq is not enough on its own. The tag worker drains
         * FSM queues, but it does not promote nocq entries into TXQ. Kick the
         * TX-window scheduler unless the caller is batching a fragment group.
         */
        ttp_noc_requ (lt);
    }

    TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_ENQ, TTP_OP__TTP_PAYLOAD);
    TTP_DB1 ("%s: enqueue %s len:%d tx:%d mark:%s\n", __FUNCTION__,
             TTP_EVENT_NAME (ev->evt), ev->psi.noc_len, ev->psi.txi_seq,
             TTP_EVENTS_FENCE_TO_STR (ev->mrk));
}

void ttp_noc_enqu (struct ttp_fsm_event *ev)
{
    ttp_noc_enqu_common (ev, true);
}

void ttp_noc_enqu_defer (struct ttp_fsm_event *ev)
{
    ttp_noc_enqu_common (ev, false);
}

void ttp_noc_kick (u64 kid)
{
    struct ttp_link_tag *lt;

    if ((lt = ttp_rbtree_tag_get (kid))) {
        ttp_noc_requ (lt);
    }
}


void __init ttp_fsm_init (void)
{
    int vi, hv, bk;
    struct ttp_fsm_event *ev;
    struct ttp_fsm_evlog *lg;
    struct ttp_link_tag *lt;

    mutex_init (&ttp_global_root_head.event_mutx);
    mutex_init (&ttp_global_root_head.evlog_mutx);

    /* initialize pool and queue list heads */
    skb_queue_head_init (&ttp_global_root_head.skb_head);
    INIT_LIST_HEAD (&ttp_global_root_head.pool_head);
    INIT_LIST_HEAD (&ttp_global_root_head.rxq_head);
    INIT_LIST_HEAD (&ttp_global_root_head.txq_head);
    INIT_LIST_HEAD (&ttp_global_root_head.akq_head);
    INIT_LIST_HEAD (&ttp_global_root_head.inq_head);
    INIT_LIST_HEAD (&ttp_global_root_head.evlog_head);

    /* initialize array: create pool */
    for (vi = 0; vi < TTP_EVENTS_POOL_SIZE; vi++) {
        ev = &ttp_global_root_head.event_arr[vi];

        ev->rsk = NULL;
        ev->tsk = NULL;
        ev->idx = TTP_EVENTS_INDX_OF (ev);
        ev->evt = TTP_EV__invalid;
        ev->kid = 0;
        ev->mrk = TTP_EVENTS_FENCE_POOL_ELEM;

        lg = &ttp_global_root_head.evlog_arr[vi];
        lg->ts = jiffies;

        ttp_stats.pool++;

        mutex_lock (&ttp_global_root_head.event_mutx);

        list_add_tail (&ev->elm, &ttp_global_root_head.pool_head);
        list_add_tail (&lg->lm, &ttp_global_root_head.evlog_head);

        mutex_unlock (&ttp_global_root_head.event_mutx);
    }

    /* setup timers */
    timer_setup (&ttp_global_root_head.timer_head, &ttp_fsm_global_timer_callback, 0);
    INIT_WORK   (&ttp_global_root_head.work_queue, ttp_do_global_work);
    ttp_global_root_head.tag_rbroot = RB_ROOT;

    spin_lock_init (&ttp_global_root_head.spin_lock);

    for (hv = 0; hv < TTP_TAG_TBL_SIZE; hv++) {
        for (bk = 0; bk < TTP_TAG_TBL_BKTS_NUM; bk++) {
            lt = &ttp_link_tag_tbl_0[hv][bk];
            timer_setup (&lt->tmr, &ttp_fsm_tag_timer_callback, 0);
            INIT_WORK (&lt->wkq, ttp_do_tag_work);
            INIT_LIST_HEAD (&lt->ncq);
            lt->rx_ooo = ttp_rx_ooo_tbl_0[hv][bk];
            ttp_tag_reset (lt);

            lt = &ttp_link_tag_tbl_1[hv][bk];
            timer_setup (&lt->tmr, &ttp_fsm_tag_timer_callback, 0);
            INIT_WORK (&lt->wkq, ttp_do_tag_work);
            INIT_LIST_HEAD (&lt->ncq);
            lt->rx_ooo = ttp_rx_ooo_tbl_1[hv][bk];
            ttp_tag_reset (lt);

            lt = &ttp_link_tag_tbl_2[hv][bk];
            timer_setup (&lt->tmr, &ttp_fsm_tag_timer_callback, 0);
            INIT_WORK (&lt->wkq, ttp_do_tag_work);
            INIT_LIST_HEAD (&lt->ncq);
            lt->rx_ooo = ttp_rx_ooo_tbl_2[hv][bk];
            ttp_tag_reset (lt);
        }
    }
}

void ttp_fsm_exit (void)
{
    int vi, hv, bk;
    struct ttp_fsm_event *ev;

    mutex_lock (&ttp_global_root_head.event_mutx);

    /* free all allocated buffers */
    for (vi = 0; vi < TTP_EVENTS_POOL_SIZE; vi++) {
        ev = &ttp_global_root_head.event_arr[vi];
        kfree_skb (ev->rsk);
        ev->rsk = NULL;
        kfree_skb (ev->tsk);
        ev->tsk = NULL;
        ttp_evt_pput_locked (ev);
    }

    /* delete all pool timers */
    for (hv = 0; hv < TTP_TAG_TBL_SIZE; hv++) {
        for (bk = 0; bk < TTP_TAG_TBL_BKTS_NUM; bk++) {
            del_timer (&ttp_link_tag_tbl_0[hv][bk].tmr);
            del_timer (&ttp_link_tag_tbl_1[hv][bk].tmr);
            del_timer (&ttp_link_tag_tbl_2[hv][bk].tmr);
        }
    }
    del_timer (&ttp_global_root_head.timer_head);

    mutex_unlock (&ttp_global_root_head.event_mutx);
}
