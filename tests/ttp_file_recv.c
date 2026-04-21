#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/ttp_socket.h"

#include "ttp_sock_common.h"

#define TTP_FILE_MAGIC 0x54545046u
#define TTP_FILE_VERSION 1u
#define TTP_FILE_MAX_CHUNK (64u * 1024u)

struct ttp_file_header {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint64_t file_size;
};

static int ttp_recv_full_msg(int fd, void *buf, size_t len)
{
    for (;;) {
        ssize_t rc = recv(fd, buf, len, 0);

        if (rc == (ssize_t)len) {
            return 0;
        }
        if (rc == 0) {
            fprintf(stderr, "peer closed before delivering a complete message\n");
            return -1;
        }
        if (rc > 0) {
            fprintf(stderr, "unexpected message size: expected %zu, got %zd\n", len, rc);
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        perror("recv");
        return -1;
    }
}

int main(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    struct ttp_file_header header;
    unsigned char *buffer = NULL;
    uint64_t received = 0;
    FILE *out = NULL;
    int family;
    int fd = -1;
    int conn_fd = -1;
    int rc = 1;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <ifname> <vci> <output-file>\n", argv[0]);
        return 2;
    }

    buffer = malloc(TTP_FILE_MAX_CHUNK);
    if (!buffer) {
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
    local.st_ifindex = if_nametoindex(argv[1]);
    local.st_vci = (unsigned char)atoi(argv[2]);
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

    printf("listening on %s vci=%u, waiting for file...\n", argv[1], (unsigned)local.st_vci);
    conn_fd = accept(fd, NULL, NULL);
    if (conn_fd < 0) {
        perror("accept");
        goto out;
    }

    if (ttp_recv_full_msg(conn_fd, &header, sizeof(header)) < 0) {
        goto out;
    }
    if (header.magic != TTP_FILE_MAGIC || header.version != TTP_FILE_VERSION) {
        fprintf(stderr, "invalid file header received\n");
        goto out;
    }

    out = fopen(argv[3], "wb");
    if (!out) {
        perror("fopen(output-file)");
        goto out;
    }

    while (received < header.file_size) {
        size_t want = TTP_FILE_MAX_CHUNK;
        ssize_t got;

        if (header.file_size - received < want) {
            want = (size_t)(header.file_size - received);
        }

        got = recv(conn_fd, buffer, want, 0);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv(data)");
            goto out;
        }
        if (got == 0) {
            fprintf(stderr, "peer closed before file was complete (%llu/%llu bytes)\n",
                    (unsigned long long)received,
                    (unsigned long long)header.file_size);
            goto out;
        }

        if (fwrite(buffer, 1, (size_t)got, out) != (size_t)got) {
            perror("fwrite");
            goto out;
        }
        received += (uint64_t)got;
    }

    if (recv(conn_fd, buffer, 1, 0) != 0) {
        if (errno) {
            perror("recv(expect eof)");
        } else {
            fprintf(stderr, "expected EOF after file payload\n");
        }
        goto out;
    }

    printf("received %llu bytes into %s\n",
           (unsigned long long)received, argv[3]);
    rc = 0;

out:
    if (out) {
        fclose(out);
    }
    if (conn_fd >= 0) {
        close(conn_fd);
    }
    if (fd >= 0) {
        close(fd);
    }
    free(buffer);
    return rc;
}
