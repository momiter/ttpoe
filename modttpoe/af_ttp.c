// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/net.h>

#include "socket.h"

int ttp_socket_family = AF_TTP;
module_param_named(socket_family, ttp_socket_family, int, 0444);
MODULE_PARM_DESC(socket_family,
                 "Experimental AF_TTP/PF_TTP family number. Must be unused at runtime.");

static struct net_proto_family ttp_family_ops = {
    .family = AF_TTP,
    .create = ttp_create,
    .owner = THIS_MODULE,
};

int ttp_socket_init(void)
{
    ttp_family_ops.family = ttp_socket_family;
    ttp_proto_ops.family = ttp_socket_family;
    return sock_register(&ttp_family_ops);
}

void ttp_socket_exit(void)
{
    sock_unregister(ttp_socket_family);
}
