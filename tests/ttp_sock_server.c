#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../include/ttp_socket.h"
#include "ttp_sock_common.h"

int main(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    struct sockaddr_ttp peer = {0};
    char buffer[1024];
    struct iovec iov;
    struct msghdr msg;
    size_t recv_len = sizeof(buffer) - 1;
    size_t display_len;
    int recv_flags = 0;
    int truncated = 0;
    int family;
    int fd;
    ssize_t n;

    if (argc < 4 || argc > 6) {
        fprintf(stderr,
                "usage: %s <ifname> <vci> <peer-node> [recv-len] [--dontwait]\n",
                argv[0]);
        fprintf(stderr, "note: both peers actively connect before the recv side blocks for payload\n");
        return 2;
    }

    if (argc >= 5) {
        recv_len = (size_t)strtoul(argv[4], NULL, 0);
        if (!recv_len || recv_len >= sizeof(buffer)) {
            fprintf(stderr, "invalid recv-len '%s' (must be 1-%zu)\n",
                    argv[4], sizeof(buffer) - 1);
            return 2;
        }
    }
    if (argc == 6) {
        if (strcmp(argv[5], "--dontwait") != 0) {
            fprintf(stderr, "unsupported flag '%s'\n", argv[5]);
            return 2;
        }
        recv_flags |= MSG_DONTWAIT;
    }

    family = ttp_socket_family_detect();
    fd = socket(family, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    local.st_family = family;
    local.st_ifindex = if_nametoindex(argv[1]);
    local.st_vci = (unsigned char)atoi(argv[2]);
    if (!local.st_ifindex) {
        perror("if_nametoindex");
        close(fd);
        return 1;
    }

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }

    peer.st_family = family;
    peer.st_ifindex = local.st_ifindex;
    peer.st_vci = local.st_vci;
    if (ttp_parse_node(argv[3], peer.st_node) != 0) {
        fprintf(stderr, "invalid peer node '%s'\n", argv[3]);
        close(fd);
        return 1;
    }

    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    printf("connected over family %d, waiting for payload...\n", family);

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = recv_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    n = recvmsg(fd, &msg, recv_flags);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "recvmsg: no data available (nonblocking)\n");
        } else {
            perror("recvmsg");
        }
        close(fd);
        return 1;
    }

    truncated = !!(msg.msg_flags & MSG_TRUNC);
    display_len = truncated ? recv_len : (size_t)n;
    buffer[display_len] = '\0';
    printf("received %zd bytes over family %d (copied=%zu trunc=%s): %s\n",
           n, family, display_len, truncated ? "yes" : "no",
           buffer);
    close(fd);
    return 0;
}
