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

#include <linux/ctype.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
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
#include <linux/seq_file.h>
#include <net/addrconf.h>
#include <net/ip.h>

#include <ttp.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "noc.h"
#include "print.h"

#define TTP_PROC_LGH_HDR_1 "off", "file", "line", "age", "vc", "tag", "B", "state/action"
/*                         tag   off  position     age    vc  tag   B   state/action */
#define TTP_PROC_LGH_FMT_1 "%3d  %3s  %8s:%-4s  %5s "    "%2s %3s  %1s  %-12s  "
#define TTP_PROC_LOG_FMT_1 "%3d  %3d  %8s:%-4d  %5llu "  "%2d %3x  %1d  %-12s  "
#define TTP_PROC_LGX_FMT_1 "%3d  %3d  %8s:%-4d  %5llu "  "%2s %3s  %1c      "   "  %6s  "

#define TTP_PROC_LGH_HDR_2 "event-name", "opcode-name", "response", "dir", "len", \
        "rx-seq", "tx-seq", "next-state", "next-sef", "kid.idx"

/*                          event-name  opcode-name  response dir  len  rx-seq
 *   tx-seq   next-state  next-sef  kid */
#define TTP_PROC_LGH_FMT_2  "%-20s  "   "%-16s  "    "%-13s   %3s  %4s  %7s  "  \
    "%7s  "  "%12s  "    "%-13s   %-18s\n"
#define TTP_PROC_LOG_FMT_2  "%-20s  "   "%-16s  "    "%-13s   %9s  "   "%7d  "  \
    "%7d  "  "%12s  "    "%-13s   0x%016llx.%d  %d\n"
#define TTP_PROC_LGX_FMT_2  "%-20s  "   "%-16s  "    "%-13s   %3s  %4d  %7d  "  \
    "%7d  "  "%12s  "    "%-13s   0x%016llx.%d  %d\n"

#define TTP_EV_LOG_SEQ_PRINTF(aa,tos)      \
    seq_printf (seq, TTP_PROC_LGX_FMT_1    \
                TTP_PROC_LGX_FMT_2, ct++,  \
                TTP_EV_LOG_INDX_OF (lg),   \
                lg->fl, lg->ln,            \
                max (0ULL, lts - lg->ts),  \
                "-","-",'-',               \
                TTP_EVLOG_GLYPH (aa),      \
                TTP_EVLOG_NAME (aa),       \
                TTP_OPCODE_NAME (lg->op),  \
                tos,                       \
                TTP_EVLOG_DIR (aa),        \
                lg->sz, lg->rx, lg->tx,    \
                "-", "-",                  \
                cpu_to_be64 (lg->kd),      \
                lg->ix, lg->rf);

static int ttpoe_proc_ev_log_show (struct seq_file *seq, void *v)
{
    u64 lts = 0;
    int ct  = 0;
    char szs[10];
    struct ttp_fsm_evlog *lg;

    if (!ttp_stats.evlog) {
        return 0;
    }

    if (0 == mutex_trylock (&ttp_global_root_head.event_mutx)) {
        return 0;
    }

    seq_printf (seq, TTP_PROC_LGH_FMT_1 TTP_PROC_LGH_FMT_2,
                ttp_stats.evlog, TTP_PROC_LGH_HDR_1, TTP_PROC_LGH_HDR_2);

    list_for_each_entry_reverse (lg, &ttp_global_root_head.evlog_head, lm) {
        lts = lts ? lts : lg->ts;

        switch (lg->ev) {
        case TTP_LG__TTP_INIT ... TTP_LG__TIMER_DELETE:
            snprintf (szs, 10, "%5s", "-");
            TTP_EV_LOG_SEQ_PRINTF (lg->ev, szs);
            break;

        default:
            if (!lg->kd) {
                continue;
            }
            if (TTP_RS__PAYLOAD == lg->rs) {
                if (lg->sz) {
                    snprintf (szs, 10, "%3s  %4d", TTP_EVLOG_DIR (lg->ev), (int)lg->sz);
                }
                else {
                    snprintf (szs, 10, "%3s  %4s", TTP_EVLOG_DIR (lg->ev), ".");
                }
            }
            else if (TTP_EV__RXQ__TTP_PAYLOAD == lg->ev) {
                snprintf (szs, 10, "%3s  %4d", TTP_EVLOG_DIR (lg->ev), (int)lg->sz);
            }
            else if (TTP_EV__TXQ__TTP_PAYLOAD == lg->ev) {
                snprintf (szs, 10, "%3s  %4d", TTP_EVLOG_DIR (lg->ev), (int)lg->sz);
            }
            else {
                snprintf (szs, 10, "%3s  %4d", TTP_EVLOG_DIR (lg->ev), 0);
            }

            seq_printf (seq, TTP_PROC_LOG_FMT_1 TTP_PROC_LOG_FMT_2,
                        ct++,
                        TTP_EV_LOG_INDX_OF (lg),
                        lg->fl, lg->ln,
                        max (0ULL, lts - lg->ts),
                        lg->vc, lg->hv, lg->bk,
                        TTP_STATE_NAME (lg->cs),
                        TTP_EVENT_NAME (lg->ev),
                        TTP_OPCODE_NAME (lg->op),
                        TTP_RESPONSE_NAME (lg->rs),
                        szs, lg->rx, lg->tx,
                        TTP_STATE_NAME (lg->ns),
                        TTP_SEF_NAME (lg->ns),
                        cpu_to_be64 (lg->kd), lg->ix, lg->rf);

            break;
        } /* switch */
        lts = lg->ts;

        /* Enable below 2 lines to get mapping of 'ps' to line, file, and function.*
        if (lg->ln) {
            seq_printf (seq, "          `-> %s:%d %s()\n", &lg->fl[55], lg->ln, lg->fn);
        } */
    } /* list-for-each */

    mutex_unlock (&ttp_global_root_head.event_mutx);
    return 0;
}


static int ttpoe_proc_pool_show (struct seq_file *seq, void *v)
{
    int vi;
    struct ttp_fsm_event *ev;

    if (!seq) {
        return 0;
    }

    seq_printf (seq, "free pool: (%d) elems\n", ttp_stats.pool);
    if (ttp_stats.queue || ttp_stats.nocq) {
        ttp_print_evt_hdr (seq);
    }

    for (vi = 0; vi < TTP_EVENTS_POOL_SIZE; vi++) {
        ev = &ttp_global_root_head.event_arr[vi];
        ttp_print_evt_val (seq, ev);
    }
    return 0;
}


static int ttpoe_proc_queue_show (struct seq_file *seq, void *v)
{
    struct ttp_fsm_event *ev, *xv;

    if (!seq) {
        return 0;
    }

    seq_printf (seq, "events rxq/txq/ackq/intq: (%d) elems\n", ttp_stats.queue);
    ttp_print_evt_hdr (seq);

    if (0 == mutex_trylock (&ttp_global_root_head.event_mutx)) {
        return 0;
    }

    list_for_each_entry_safe (ev, xv, &ttp_global_root_head.rxq_head, elm) {
        ttp_print_evt_val (seq, ev);
    }

    list_for_each_entry_safe (ev, xv, &ttp_global_root_head.txq_head, elm) {
        ttp_print_evt_val (seq, ev);
    }

    list_for_each_entry_safe (ev, xv, &ttp_global_root_head.akq_head, elm) {
        ttp_print_evt_val (seq, ev);
    }

    list_for_each_entry_safe (ev, xv, &ttp_global_root_head.inq_head, elm) {
        ttp_print_evt_val (seq, ev);
    }

    mutex_unlock (&ttp_global_root_head.event_mutx);
    return 0;
}


static int ttpoe_proc_tags_show (struct seq_file *seq, void *v)
{
    int hv, ct0 = 0, ct1 = 0;

    if (!seq) {
        return 0;
    }

    for (hv = 0; hv < TTP_TAG_TBL_SIZE; hv++) {
        ct0 += ttp_link_tag_tbl_0[hv][0].valid ? 1 : 0;
        ct1 += ttp_link_tag_tbl_0[hv][1].valid ? 1 : 0;

        ct0 += ttp_link_tag_tbl_1[hv][0].valid ? 1 : 0;
        ct1 += ttp_link_tag_tbl_1[hv][1].valid ? 1 : 0;

        ct0 += ttp_link_tag_tbl_2[hv][0].valid ? 1 : 0;
        ct1 += ttp_link_tag_tbl_2[hv][1].valid ? 1 : 0;
    }

    if (ct0 + ct1) {
        ttp_print_tag_hdr (seq);
        for (hv = 0; hv < TTP_TAG_TBL_SIZE; hv++) {
            ttp_print_tag_val (seq, &ttp_link_tag_tbl_0[hv][0]);
            ttp_print_tag_val (seq, &ttp_link_tag_tbl_0[hv][1]);

            ttp_print_tag_val (seq, &ttp_link_tag_tbl_1[hv][0]);
            ttp_print_tag_val (seq, &ttp_link_tag_tbl_1[hv][1]);

            ttp_print_tag_val (seq, &ttp_link_tag_tbl_2[hv][0]);
            ttp_print_tag_val (seq, &ttp_link_tag_tbl_2[hv][1]);
        }
    }

    return 0;
}


static int ttpoe_proc_rbtree_show (struct seq_file *seq, void *v)
{
    struct rb_node *nd;
    struct ttp_link_tag *lt;

    if (!seq) {
        return 0;
    }

    ttp_print_tag_hdr (seq);
    for (nd = rb_first (&ttp_global_root_head.tag_rbroot); nd; nd = rb_next (nd)) {
        lt = rb_entry (nd, struct ttp_link_tag, rbn);
        ttp_print_tag_val (seq, lt);
    }

    return 0;
}


static int ttpoe_proc_target_show (struct seq_file *seq, void *v)
{
    if (!seq) {
        return 0;
    }

    seq_printf (seq, "target: mac:%*phC valid:%d vci:%d gw:%d ipv4:%d ipa:%pI4\n",
                ETH_ALEN, ttp_debug_target.mac, ttp_debug_target.ve, ttp_debug_target.vc,
                ttp_debug_target.gw, ttp_debug_target.ip, &ttp_debug_target.ipa);

    return 0;
}

static void ttpoe_proc_stats_reset (void)
{
#define TTP_STATS_ZERO(_v) atomic_set (&ttp_stats._v, 0)
#define TTP_STATS64_ZERO(_v) atomic64_set (&ttp_stats._v, 0)
    TTP_STATS_ZERO (tx_payload_pkts);
    TTP_STATS_ZERO (rx_payload_pkts);
    TTP_STATS_ZERO (tx_retrans_pkts);
    TTP_STATS64_ZERO (tx_payload_bytes);
    TTP_STATS64_ZERO (rx_payload_bytes);
    TTP_STATS64_ZERO (tx_retrans_bytes);

    TTP_STATS_ZERO (tx_open);
    TTP_STATS_ZERO (rx_open);
    TTP_STATS_ZERO (tx_close);
    TTP_STATS_ZERO (rx_close);
    TTP_STATS_ZERO (tx_ack);
    TTP_STATS_ZERO (rx_ack);
    TTP_STATS_ZERO (tx_nack);
    TTP_STATS_ZERO (rx_nack);
    TTP_STATS_ZERO (tx_nack_full);
    TTP_STATS_ZERO (rx_nack_full);
    TTP_STATS_ZERO (tx_nack_nolink);
    TTP_STATS_ZERO (rx_nack_nolink);

    TTP_STATS_ZERO (rx_duplicate_payloads);
    TTP_STATS_ZERO (rx_future_payloads);
    TTP_STATS_ZERO (stale_nack_ignored);
    TTP_STATS_ZERO (duplicate_nack_ignored);
    TTP_STATS_ZERO (payload_timeouts);
    TTP_STATS_ZERO (full_backoff_timeouts);
#undef TTP_STATS_ZERO
#undef TTP_STATS64_ZERO
}

static int ttpoe_proc_stats_show (struct seq_file *seq, void *v)
{
    if (!seq) {
        return 0;
    }

#define TTP_STATS_PRINT(_v) seq_printf (seq, #_v ": %d\n", atomic_read (&ttp_stats._v))
#define TTP_STATS64_PRINT(_v) seq_printf (seq, #_v ": %lld\n", atomic64_read (&ttp_stats._v))
    TTP_STATS_PRINT (tx_payload_pkts);
    TTP_STATS_PRINT (rx_payload_pkts);
    TTP_STATS_PRINT (tx_retrans_pkts);
    TTP_STATS64_PRINT (tx_payload_bytes);
    TTP_STATS64_PRINT (rx_payload_bytes);
    TTP_STATS64_PRINT (tx_retrans_bytes);

    TTP_STATS_PRINT (tx_open);
    TTP_STATS_PRINT (rx_open);
    TTP_STATS_PRINT (tx_close);
    TTP_STATS_PRINT (rx_close);
    TTP_STATS_PRINT (tx_ack);
    TTP_STATS_PRINT (rx_ack);
    TTP_STATS_PRINT (tx_nack);
    TTP_STATS_PRINT (rx_nack);
    TTP_STATS_PRINT (tx_nack_full);
    TTP_STATS_PRINT (rx_nack_full);
    TTP_STATS_PRINT (tx_nack_nolink);
    TTP_STATS_PRINT (rx_nack_nolink);

    TTP_STATS_PRINT (rx_duplicate_payloads);
    TTP_STATS_PRINT (rx_future_payloads);
    TTP_STATS_PRINT (stale_nack_ignored);
    TTP_STATS_PRINT (duplicate_nack_ignored);
    TTP_STATS_PRINT (payload_timeouts);
    TTP_STATS_PRINT (full_backoff_timeouts);
#undef TTP_STATS_PRINT
#undef TTP_STATS64_PRINT

    seq_printf (seq, "queue: %u\n", ttp_stats.queue);
    seq_printf (seq, "nocq: %u\n", ttp_stats.nocq);
    seq_printf (seq, "pool: %u\n", ttp_stats.pool);
    seq_printf (seq, "skb_rx: %d\n", atomic_read (&ttp_stats.skb_rx));
    seq_printf (seq, "skb_tx: %d\n", atomic_read (&ttp_stats.skb_tx));
    seq_printf (seq, "frames: %d\n", atomic_read (&ttp_stats.frm_ct));
    seq_printf (seq, "payload_delivered_legacy: %d\n", atomic_read (&ttp_stats.pld_ct));
    seq_printf (seq, "drops_legacy: %d\n", atomic_read (&ttp_stats.drp_ct));

    return 0;
}

static int ttpoe_proc_stats_open (struct inode *inode, struct file *file)
{
    return single_open (file, ttpoe_proc_stats_show, NULL);
}

static ssize_t ttpoe_proc_stats_write (struct file *file, const char __user *buf,
                                       size_t count, loff_t *ppos)
{
    ttpoe_proc_stats_reset ();
    return count;
}

static const struct proc_ops ttpoe_proc_stats_ops = {
    .proc_open    = ttpoe_proc_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = ttpoe_proc_stats_write,
};

static struct proc_dir_entry *ttp_proc_dir;

void ttpoe_proc_cleanup (void)
{
    if (ttp_proc_dir) {
        remove_proc_subtree ("modttpoe", init_net.proc_net);
    }
}

int __init ttpoe_proc_init (void)
{
    if (!(ttp_proc_dir = proc_mkdir ("modttpoe", init_net.proc_net))) {
        return -ENOMEM;
    }

    if (!proc_create_single ("modttpoe/ev_log", 0444,
                             init_net.proc_net, &ttpoe_proc_ev_log_show)) {
        goto out;
    }
    if (!proc_create_single ("modttpoe/pool", 0444,
                             init_net.proc_net, &ttpoe_proc_pool_show)) {
        goto out;
    }
    if (!proc_create_single ("modttpoe/queue", 0444,
                             init_net.proc_net, &ttpoe_proc_queue_show)) {
        goto out;
    }
    if (!proc_create_single ("modttpoe/tags", 0444,
                             init_net.proc_net, &ttpoe_proc_tags_show)) {
        goto out;
    }
    if (!proc_create_single ("modttpoe/rbtree", 0444,
                             init_net.proc_net, &ttpoe_proc_rbtree_show)) {
        goto out;
    }
    if (!proc_create_single ("modttpoe/target", 0444,
                             init_net.proc_net, &ttpoe_proc_target_show)) {
        goto out;
    }
    if (!proc_create ("modttpoe/stats", 0644,
                      init_net.proc_net, &ttpoe_proc_stats_ops)) {
        goto out;
    }

    return 0;

out:
    if (ttp_proc_dir) {
        remove_proc_subtree ("modttpoe", init_net.proc_net);
    }
    TTP_LOG ("proc * create failed!\n");

    return -ENOMEM;
}


void __exit ttpoe_proc_exit (void)
{
    ttpoe_proc_cleanup ();
}
