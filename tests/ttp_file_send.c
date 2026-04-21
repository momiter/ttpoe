#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/ttp_socket.h"

#include "ttp_sock_common.h"

#define TTP_FILE_MAGIC 0x54545046u
#define TTP_FILE_VERSION 1u
#define TTP_FILE_DEFAULT_CHUNK (60u * 1024u)
#define TTP_FILE_MAX_CHUNK (64u * 1024u)
#define TTP_FILE_RETRY_US 5000

struct ttp_file_header {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint64_t file_size;
};

static int ttp_send_retry(int fd, const void *buf, size_t len)
{
    const unsigned char *ptr = buf;

    for (;;) {
        ssize_t rc = send(fd, ptr, len, 0);

        if (rc == (ssize_t)len) {
            return 0;
        }
        if (rc >= 0) {
            fprintf(stderr, "short send: expected %zu, got %zd\n", len, rc);
            return -1;
        }
        if (errno == ENOBUFS || errno == ENOMEM || errno == EAGAIN || errno == EWOULDBLOCK) {
            usleep(TTP_FILE_RETRY_US);
            continue;
        }
        perror("send");
        return -1;
    }
}

int main(int argc, char **argv)
{
    struct sockaddr_ttp remote = {0};
    struct sockaddr_ttp local = {0};
    struct ttp_file_header header;
    unsigned char peer_node[3];
    unsigned char *buffer = NULL;
    size_t chunk_size = TTP_FILE_DEFAULT_CHUNK;
    uint64_t sent = 0;
    struct stat st;
    FILE *in = NULL;
    int family;
    int fd = -1;
    int rc = 1;

    if (argc < 5 || argc > 6) {
        fprintf(stderr, "usage: %s <ifname> <vci> <peer-node> <input-file> [chunk-size]\n", argv[0]);
        return 2;
    }

    if (ttp_parse_node(argv[3], peer_node) != 0) {
        fprintf(stderr, "invalid peer-node '%s'\n", argv[3]);
        return 2;
    }

    if (argc == 6) {
        chunk_size = (size_t)strtoul(argv[5], NULL, 0);
        if (!chunk_size || chunk_size > TTP_FILE_MAX_CHUNK) {
            fprintf(stderr, "invalid chunk-size '%s' (must be 1-%u)\n", argv[5], TTP_FILE_MAX_CHUNK);
            return 2;
        }
    }

    if (stat(argv[4], &st) < 0) {
        perror("stat(input-file)");
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "input-file must be a regular file\n");
        return 1;
    }

    in = fopen(argv[4], "rb");
    if (!in) {
        perror("fopen(input-file)");
        return 1;
    }

    buffer = malloc(chunk_size);
    if (!buffer) {
        perror("malloc");
        goto out;
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

    remote.st_family = family;
    remote.st_ifindex = local.st_ifindex;
    remote.st_vci = local.st_vci;
    memcpy(remote.st_node, peer_node, sizeof(peer_node));

    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        perror("connect");
        goto out;
    }

    memset(&header, 0, sizeof(header));
    header.magic = TTP_FILE_MAGIC;
    header.version = TTP_FILE_VERSION;
    header.file_size = (uint64_t)st.st_size;

    if (ttp_send_retry(fd, &header, sizeof(header)) < 0) {
        goto out;
    }

    while (sent < header.file_size) {
        size_t want = chunk_size;
        size_t got;

        if (header.file_size - sent < want) {
            want = (size_t)(header.file_size - sent);
        }

        got = fread(buffer, 1, want, in);
        if (got != want) {
            if (ferror(in)) {
                perror("fread");
                goto out;
            }
            fprintf(stderr, "unexpected EOF while reading input file\n");
            goto out;
        }

        if (ttp_send_retry(fd, buffer, got) < 0) {
            goto out;
        }
        sent += got;
    }

    if (shutdown(fd, SHUT_WR) < 0) {
        perror("shutdown(SHUT_WR)");
        goto out;
    }

    printf("sent %llu bytes from %s in chunks of %zu bytes\n",
           (unsigned long long)sent, argv[4], chunk_size);
    rc = 0;

out:
    if (fd >= 0) {
        close(fd);
    }
    free(buffer);
    if (in) {
        fclose(in);
    }
    return rc;
}
