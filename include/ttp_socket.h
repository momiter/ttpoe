/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TTP_SOCKET_H
#define TTP_SOCKET_H

#include <linux/types.h>

#define TTP_NODE_ADDR_LEN 3


#ifndef AF_TTP
#define AF_TTP 28
#endif

#define PF_TTP AF_TTP
#define SOL_TTP 0x5454

struct sockaddr_ttp {
    __u16 st_family;
    __u8  st_vci;
    __u8  st_flags;
    __u16 st_reserved;
    __u32 st_ifindex;
    __u8  st_node[TTP_NODE_ADDR_LEN];
    __u8  st_pad[5];
};

#endif
