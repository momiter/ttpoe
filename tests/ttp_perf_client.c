#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../include/ttp_socket.h"

#include "ttp_sock_common.h"

#define TTP_PERF_DEFAULT_SECONDS 10.0
#define TTP_PERF_DEFAULT_MSG_SIZE (64u * 1024u)
#define TTP_PERF_MAX_MSG_SIZE (64u * 1024u)
#define TTP_PERF_RETRY_US 1000

static double now_sec(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static int parse_double_arg(const char *text, double *value)
{
    char *end = NULL;
    double v;

    errno = 0;
    v = strtod(text, &end);
    if (errno || !end || *end || v <= 0.0) {
        return -1;
    }
    *value = v;
    return 0;
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
    if (*end || !v || v > TTP_PERF_MAX_MSG_SIZE) {
        return -1;
    }
    *value = (size_t)v;
    return 0;
}

static int ttp_send_retry(int fd, const void *buf, size_t len,
                          uint64_t *backpressure)
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
        if (errno == ENOBUFS || errno == ENOMEM || errno == EAGAIN ||
            errno == EWOULDBLOCK) {
            if (backpressure) {
                (*backpressure)++;
            }
            usleep(TTP_PERF_RETRY_US);
            continue;
        }
        if (errno == EINTR) {
            continue;
        }
        perror("send");
        return -1;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <ifname> <vci> <peer-node> [seconds] [msg-size]\n"
            "  seconds:  default %.1f\n"
            "  msg-size: default %u, max %u; suffix k/m accepted\n",
            prog, TTP_PERF_DEFAULT_SECONDS, TTP_PERF_DEFAULT_MSG_SIZE,
            TTP_PERF_MAX_MSG_SIZE);
}

int main(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    struct sockaddr_ttp remote = {0};
    unsigned char peer_node[3];
    unsigned char *buffer = NULL;
    double seconds = TTP_PERF_DEFAULT_SECONDS;
    double start;
    double end;
    double elapsed;
    size_t msg_size = TTP_PERF_DEFAULT_MSG_SIZE;
    uint64_t bytes = 0;
    uint64_t messages = 0;
    uint64_t backpressure = 0;
    int family;
    int fd = -1;
    int rc = 1;

    if (argc < 4 || argc > 6) {
        usage(argv[0]);
        return 2;
    }
    if (ttp_parse_node(argv[3], peer_node) != 0) {
        fprintf(stderr, "invalid peer-node '%s'\n", argv[3]);
        return 2;
    }
    if (argc >= 5 && parse_double_arg(argv[4], &seconds)) {
        fprintf(stderr, "invalid seconds '%s'\n", argv[4]);
        return 2;
    }
    if (argc >= 6 && parse_size_arg(argv[5], &msg_size)) {
        fprintf(stderr, "invalid msg-size '%s'\n", argv[5]);
        return 2;
    }

    buffer = malloc(msg_size);
    if (!buffer) {
        perror("malloc");
        return 1;
    }
    for (size_t i = 0; i < msg_size; i++) {
        buffer[i] = (unsigned char)(i & 0xff);
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

    start = now_sec();
    for (;;) {
        double now = now_sec();

        if (now - start >= seconds) {
            break;
        }
        if (ttp_send_retry(fd, buffer, msg_size, &backpressure) < 0) {
            goto out;
        }
        bytes += msg_size;
        messages++;
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
            fprintf(stderr, "unexpected data received while waiting for EOF\n");
            goto out;
        }
        if (errno == EINTR) {
            continue;
        }
        perror("recv(expect eof)");
        goto out;
    }

    end = now_sec();
    elapsed = end - start;
    printf("client: bytes=%llu messages=%llu msg_size=%zu elapsed=%.3f sec throughput=%.2f Mbit/s backpressure=%llu\n",
           (unsigned long long)bytes,
           (unsigned long long)messages,
           msg_size,
           elapsed,
           elapsed > 0.0 ? ((double)bytes * 8.0 / elapsed / 1000000.0) : 0.0,
           (unsigned long long)backpressure);
    rc = 0;

out:
    if (fd >= 0) {
        close(fd);
    }
    free(buffer);
    return rc;
}
