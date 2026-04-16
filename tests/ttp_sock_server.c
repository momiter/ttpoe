#include <net/if.h>
#include <arpa/inet.h>
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
#define TTP_FILE_MAGIC "TTPF"

struct ttp_file_header {
    char magic[4];
    unsigned int file_size_be;
};

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
    FILE *out = NULL;
    size_t total_expected = 0;
    size_t total_written = 0;
    ssize_t n;

    if (argc < 4 || argc > 6) {
        fprintf(stderr,
                "usage: %s <ifname> <vci> <peer-node> [recv-len] [--dontwait]\n",
                argv[0]);
        fprintf(stderr, "note: received data is written to %s\n", TTP_SOCK_OUTPUT_FILE);
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
            perror("recvmsg(header)");
        }
        close(fd);
        return 1;
    }
    if ((size_t)n < sizeof(struct ttp_file_header)) {
        fprintf(stderr, "short file header: %zd bytes\n", n);
        close(fd);
        return 1;
    }
    if (msg.msg_flags & MSG_TRUNC) {
        fprintf(stderr, "file header was truncated\n");
        close(fd);
        return 1;
    }
    {
        struct ttp_file_header header;

        memcpy(&header, buffer, sizeof(header));
        if (memcmp(header.magic, TTP_FILE_MAGIC, sizeof(header.magic)) != 0) {
            fprintf(stderr, "invalid file header magic\n");
            close(fd);
            return 1;
        }
        total_expected = ntohl(header.file_size_be);
        if (!total_expected) {
            fprintf(stderr, "invalid file size 0 in header\n");
            close(fd);
            return 1;
        }
    }

    out = fopen(TTP_SOCK_OUTPUT_FILE, "wb");
    if (!out) {
        perror("fopen(recv_test.txt)");
        close(fd);
        return 1;
    }

    while (total_written < total_expected) {
        memset(&msg, 0, sizeof(msg));
        iov.iov_base = buffer;
        iov.iov_len = recv_len;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        n = recvmsg(fd, &msg, recv_flags);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "recvmsg: no data available before file completed\n");
            } else {
                perror("recvmsg(payload)");
            }
            fclose(out);
            close(fd);
            return 1;
        }

        truncated = !!(msg.msg_flags & MSG_TRUNC);
        display_len = truncated ? recv_len : (size_t)n;
        if (display_len > (total_expected - total_written)) {
            display_len = total_expected - total_written;
        }
        if (display_len && fwrite(buffer, 1, display_len, out) != display_len) {
            fprintf(stderr, "failed to write all data to %s\n", TTP_SOCK_OUTPUT_FILE);
            fclose(out);
            close(fd);
            return 1;
        }
        total_written += display_len;

        if (truncated) {
            fprintf(stderr, "payload chunk was truncated after %zu of %zu bytes\n",
                    total_written, total_expected);
            fclose(out);
            close(fd);
            return 1;
        }
    }
    fclose(out);

    printf("received file of %zu bytes over family %d, wrote %s\n",
           total_written, family, TTP_SOCK_OUTPUT_FILE);
    close(fd);
    return 0;
}
