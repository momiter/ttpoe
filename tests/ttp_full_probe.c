#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/ttp_socket.h"

#include "ttp_sock_common.h"

#define TTP_FULL_DEFAULT_MSGS 512u
#define TTP_FULL_DEFAULT_SIZE 128u
#define TTP_FULL_MAX_SIZE (64u * 1024u)
#define TTP_FULL_RETRY_US 5000

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage:\n"
            "  %s recv <ifname> <vci> <hold-ms> [recv-buf-size]\n"
            "  %s send <ifname> <vci> <peer-node> [messages] [msg-size]\n",
            prog, prog);
}

static int send_retry(int fd, const void *buf, size_t len)
{
    for (;;) {
        ssize_t rc = send(fd, buf, len, 0);

        if (rc == (ssize_t)len) {
            return 0;
        }
        if (rc >= 0) {
            fprintf(stderr, "short send: expected %zu, got %zd\n", len, rc);
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == ENOBUFS || errno == ENOMEM ||
            errno == EAGAIN || errno == EWOULDBLOCK) {
            usleep(TTP_FULL_RETRY_US);
            continue;
        }
        perror("send");
        return -1;
    }
}

static int run_recv(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    unsigned char *buf = NULL;
    unsigned int hold_ms;
    size_t recv_size = TTP_FULL_MAX_SIZE;
    uint64_t total_bytes = 0;
    uint64_t total_msgs = 0;
    int family;
    int fd = -1;
    int conn_fd = -1;
    int rc = 1;

    if (argc < 5 || argc > 6) {
        usage(argv[0]);
        return 2;
    }

    hold_ms = (unsigned int)strtoul(argv[4], NULL, 0);
    if (argc == 6) {
        recv_size = (size_t)strtoul(argv[5], NULL, 0);
        if (!recv_size || recv_size > TTP_FULL_MAX_SIZE) {
            fprintf(stderr, "invalid recv-buf-size '%s'\n", argv[5]);
            return 2;
        }
    }

    buf = malloc(recv_size);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    family = ttp_socket_family_detect();
    fd = socket(family, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        goto out;
    }

    local.st_family = family;
    local.st_ifindex = if_nametoindex(argv[2]);
    local.st_vci = (unsigned char)atoi(argv[3]);
    if (!local.st_ifindex) {
        perror("if_nametoindex");
        goto out;
    }

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        goto out;
    }
    if (listen(fd, 1) < 0) {
        perror("listen");
        goto out;
    }

    printf("listening on %s vci=%u, hold=%u ms\n",
           argv[2], (unsigned)local.st_vci, hold_ms);
    fflush(stdout);

    conn_fd = accept(fd, NULL, NULL);
    if (conn_fd < 0) {
        perror("accept");
        goto out;
    }

    printf("accepted; delaying recv to trigger NACK_FULL\n");
    fflush(stdout);
    usleep((useconds_t)hold_ms * 1000u);

    for (;;) {
        ssize_t got = recv(conn_fd, buf, recv_size, 0);

        if (got == 0) {
            break;
        }
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            goto out;
        }
        total_msgs++;
        total_bytes += (uint64_t)got;
    }

    printf("received %llu messages, %llu bytes\n",
           (unsigned long long)total_msgs,
           (unsigned long long)total_bytes);
    rc = 0;

out:
    if (conn_fd >= 0) {
        close(conn_fd);
    }
    if (fd >= 0) {
        close(fd);
    }
    free(buf);
    return rc;
}

static int run_send(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    struct sockaddr_ttp remote = {0};
    unsigned char peer_node[3];
    unsigned char *buf = NULL;
    unsigned int messages = TTP_FULL_DEFAULT_MSGS;
    size_t msg_size = TTP_FULL_DEFAULT_SIZE;
    int family;
    int fd = -1;
    int rc = 1;

    if (argc < 5 || argc > 7) {
        usage(argv[0]);
        return 2;
    }
    if (ttp_parse_node(argv[4], peer_node) != 0) {
        fprintf(stderr, "invalid peer-node '%s'\n", argv[4]);
        return 2;
    }
    if (argc >= 6) {
        messages = (unsigned int)strtoul(argv[5], NULL, 0);
        if (!messages) {
            fprintf(stderr, "invalid messages '%s'\n", argv[5]);
            return 2;
        }
    }
    if (argc >= 7) {
        msg_size = (size_t)strtoul(argv[6], NULL, 0);
        if (!msg_size || msg_size > TTP_FULL_MAX_SIZE) {
            fprintf(stderr, "invalid msg-size '%s'\n", argv[6]);
            return 2;
        }
    }

    buf = malloc(msg_size);
    if (!buf) {
        perror("malloc");
        return 1;
    }
    for (size_t i = 0; i < msg_size; i++) {
        buf[i] = (unsigned char)(i & 0xff);
    }

    family = ttp_socket_family_detect();
    fd = socket(family, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        goto out;
    }

    local.st_family = family;
    local.st_ifindex = if_nametoindex(argv[2]);
    local.st_vci = (unsigned char)atoi(argv[3]);
    if (!local.st_ifindex) {
        perror("if_nametoindex");
        goto out;
    }
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        goto out;
    }

    remote.st_family = family;
    remote.st_ifindex = local.st_ifindex;
    remote.st_vci = local.st_vci;
    memcpy(remote.st_node, peer_node, sizeof(peer_node));

    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        perror("connect");
        goto out;
    }

    for (unsigned int i = 0; i < messages; i++) {
        buf[0] = (unsigned char)(i & 0xff);
        if (send_retry(fd, buf, msg_size) < 0) {
            goto out;
        }
    }

    if (shutdown(fd, SHUT_WR) < 0) {
        perror("shutdown(SHUT_WR)");
        goto out;
    }

    for (;;) {
        unsigned char byte;
        ssize_t got = recv(fd, &byte, 1, 0);

        if (got == 0) {
            break;
        }
        if (got > 0) {
            fprintf(stderr, "unexpected peer data while waiting EOF\n");
            goto out;
        }
        if (errno == EINTR) {
            continue;
        }
        perror("recv(expect eof)");
        goto out;
    }

    printf("sent %u messages, %zu bytes each\n", messages, msg_size);
    rc = 0;

out:
    if (fd >= 0) {
        close(fd);
    }
    free(buf);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "recv") == 0) {
        return run_recv(argc, argv);
    }
    if (strcmp(argv[1], "send") == 0) {
        return run_send(argc, argv);
    }
    usage(argv[0]);
    return 2;
}
