#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../include/ttp_socket.h"

#include "ttp_sock_common.h"

#define TTP_PERF_DEFAULT_RECV_SIZE (64u * 1024u)
#define TTP_PERF_MAX_RECV_SIZE (64u * 1024u)

static double now_sec(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static int parse_size_arg(const char *text, size_t *value)
{
    char *end = NULL;
    unsigned long long v;

    errno = 0;
    v = strtoull(text, &end, 0);
    if (errno || !end) {
        return -1;
    }
    if (*end == 'k' || *end == 'K') {
        v *= 1024ULL;
        end++;
    } else if (*end == 'm' || *end == 'M') {
        v *= 1024ULL * 1024ULL;
        end++;
    }
    if (*end || !v || v > TTP_PERF_MAX_RECV_SIZE) {
        return -1;
    }
    *value = (size_t)v;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <ifname> <vci> [recv-size]\n"
            "  recv-size: default %u, max %u; suffix k/m accepted\n",
            prog, TTP_PERF_DEFAULT_RECV_SIZE, TTP_PERF_MAX_RECV_SIZE);
}

int main(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    unsigned char *buffer = NULL;
    size_t recv_size = TTP_PERF_DEFAULT_RECV_SIZE;
    uint64_t bytes = 0;
    uint64_t messages = 0;
    double start = 0.0;
    double end = 0.0;
    double elapsed;
    int family;
    int fd = -1;
    int conn_fd = -1;
    int rc = 1;

    if (argc < 3 || argc > 4) {
        usage(argv[0]);
        return 2;
    }
    if (argc == 4 && parse_size_arg(argv[3], &recv_size)) {
        fprintf(stderr, "invalid recv-size '%s'\n", argv[3]);
        return 2;
    }

    buffer = malloc(recv_size);
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

    printf("server: listening on %s vci=%u recv_size=%zu\n",
           argv[1], (unsigned)local.st_vci, recv_size);
    fflush(stdout);

    conn_fd = accept(fd, NULL, NULL);
    if (conn_fd < 0) {
        perror("accept");
        goto out;
    }

    for (;;) {
        ssize_t got = recv(conn_fd, buffer, recv_size, 0);

        if (got == 0) {
            end = now_sec();
            break;
        }
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            goto out;
        }
        if (!messages) {
            start = now_sec();
        }
        bytes += (uint64_t)got;
        messages++;
    }

    if (!messages) {
        elapsed = 0.0;
    } else {
        elapsed = end - start;
    }
    printf("server: bytes=%llu messages=%llu elapsed=%.3f sec throughput=%.2f Mbit/s\n",
           (unsigned long long)bytes,
           (unsigned long long)messages,
           elapsed,
           elapsed > 0.0 ? ((double)bytes * 8.0 / elapsed / 1000000.0) : 0.0);
    rc = 0;

out:
    if (conn_fd >= 0) {
        close(conn_fd);
    }
    if (fd >= 0) {
        close(fd);
    }
    free(buffer);
    return rc;
}
