#include <fcntl.h>
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

#define TTP_SOCK_OUTPUT_FILE "./recv_test.txt"
#define TTP_SOCK_MAX_MESSAGE (64 * 1024)

int main(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    char *buffer = NULL;
    struct iovec iov;
    struct msghdr msg;
    size_t recv_len = TTP_SOCK_MAX_MESSAGE;
    size_t display_len;
    int recv_flags = 0;
    int truncated = 0;
    int expect_eof = 0;
    int family;
    int fd;
    int conn_fd = -1;
    FILE *out = NULL;
    ssize_t n;
    int i;

    if (argc < 3 || argc > 6) {
        fprintf(stderr,
                "usage: %s <ifname> <vci> [recv-len] [--dontwait] [--expect-eof]\n",
                argv[0]);
        fprintf(stderr, "note: received data is written to %s\n", TTP_SOCK_OUTPUT_FILE);
        return 2;
    }

    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--dontwait") == 0) {
            recv_flags |= MSG_DONTWAIT;
            continue;
        }
        if (strcmp(argv[i], "--expect-eof") == 0) {
            expect_eof = 1;
            continue;
        }
        if (recv_len == TTP_SOCK_MAX_MESSAGE) {
            recv_len = (size_t)strtoul(argv[i], NULL, 0);
            if (!recv_len || recv_len > TTP_SOCK_MAX_MESSAGE) {
                fprintf(stderr, "invalid recv-len '%s' (must be 1-%d)\n",
                        argv[i], TTP_SOCK_MAX_MESSAGE);
                return 2;
            }
            continue;
        }
        fprintf(stderr, "unsupported argument '%s'\n", argv[i]);
        return 2;
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

    if (listen(fd, 1) < 0) {
        perror("listen");
        close(fd);
        return 1;
    }

    if (recv_flags & MSG_DONTWAIT) {
        int fl = fcntl(fd, F_GETFL, 0);

        if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
            perror("fcntl(O_NONBLOCK)");
            close(fd);
            return 1;
        }
    }

    printf("listening over family %d, waiting for connection...\n", family);
    conn_fd = accept(fd, NULL, NULL);
    if (conn_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "accept: no pending connection (nonblocking)\n");
        } else {
            perror("accept");
        }
        close(fd);
        return 1;
    }

    buffer = malloc(recv_len);
    if (!buffer) {
        perror("malloc(buffer)");
        close(conn_fd);
        close(fd);
        return 1;
    }

    printf("accepted connection over family %d, waiting for payload...\n", family);

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = recv_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    n = recvmsg(conn_fd, &msg, recv_flags);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "recvmsg: no data available (nonblocking)\n");
        } else {
            perror("recvmsg");
        }
        free(buffer);
        close(conn_fd);
        close(fd);
        return 1;
    }

    out = fopen(TTP_SOCK_OUTPUT_FILE, "wb");
    if (!out) {
        perror("fopen(recv_test.txt)");
        free(buffer);
        close(conn_fd);
        close(fd);
        return 1;
    }

    truncated = !!(msg.msg_flags & MSG_TRUNC);
    display_len = truncated ? recv_len : (size_t)n;
    if (display_len && fwrite(buffer, 1, display_len, out) != display_len) {
        fprintf(stderr, "failed to write all data to %s\n", TTP_SOCK_OUTPUT_FILE);
        fclose(out);
        free(buffer);
        close(conn_fd);
        close(fd);
        return 1;
    }
    fclose(out);

    printf("received %zd bytes over family %d (copied=%zu trunc=%s), wrote %s\n",
           n, family, display_len, truncated ? "yes" : "no", TTP_SOCK_OUTPUT_FILE);

    if (expect_eof) {
        n = recvmsg(conn_fd, &msg, 0);
        if (n < 0) {
            perror("recvmsg(expect eof)");
            close(conn_fd);
            close(fd);
            return 1;
        }
        if (n != 0) {
            fprintf(stderr, "expected EOF after payload, got %zd bytes\n", n);
            close(conn_fd);
            close(fd);
            return 1;
        }
        printf("peer EOF observed after payload\n");
    }

    free(buffer);
    close(conn_fd);
    close(fd);
    return 0;
}
