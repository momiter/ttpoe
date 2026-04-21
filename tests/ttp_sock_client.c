#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/ttp_socket.h"
#include "ttp_sock_common.h"

#define TTP_SOCK_INPUT_FILE "./test.txt"
#define TTP_SOCK_MAX_MESSAGE (64 * 1024)

static long input_file_size(FILE *fp)
{
    long file_size;

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek(test.txt)");
        return -1;
    }

    file_size = ftell(fp);
    if (file_size < 0) {
        perror("ftell(test.txt)");
        return -1;
    }
    if (file_size == 0) {
        fprintf(stderr, "%s is empty\n", TTP_SOCK_INPUT_FILE);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek(test.txt)");
        return -1;
    }

    return file_size;
}

int main(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    struct sockaddr_ttp peer = {0};
    char *payload = NULL;
    int family;
    int fd;
    int linger_ms = -1;
    int do_shutdown_wr = 0;
    FILE *fp = NULL;
    long file_size;
    ssize_t n;
    int i;

    if (argc < 4 || argc > 6) {
        fprintf(stderr,
                "usage: %s <ifname> <vci> <peer-node> [linger-ms] [--shutdown-wr]\n",
                argv[0]);
        fprintf(stderr, "note: send data is read from %s\n", TTP_SOCK_INPUT_FILE);
        return 2;
    }

    for (i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--shutdown-wr") == 0) {
            do_shutdown_wr = 1;
            continue;
        }
        if (linger_ms < 0) {
            char *end = NULL;

            linger_ms = (int)strtol(argv[i], &end, 0);
            if (!end || *end != '\0' || linger_ms < 0) {
                fprintf(stderr, "invalid linger-ms '%s'\n", argv[i]);
                return 2;
            }
            continue;
        }
        fprintf(stderr, "unsupported argument '%s'\n", argv[i]);
        return 2;
    }

    fp = fopen(TTP_SOCK_INPUT_FILE, "rb");
    if (!fp) {
        perror("fopen(test.txt)");
        return 1;
    }

    file_size = input_file_size(fp);
    if (file_size < 0) {
        fclose(fp);
        return 1;
    }
    if ((unsigned long)file_size > TTP_SOCK_MAX_MESSAGE) {
        fprintf(stderr, "%s is too large: %ld bytes (max %d)\n",
                TTP_SOCK_INPUT_FILE, file_size, TTP_SOCK_MAX_MESSAGE);
        fclose(fp);
        return 1;
    }
    payload = malloc((size_t)file_size);
    if (!payload) {
        perror("malloc(payload)");
        fclose(fp);
        return 1;
    }
    if (fread(payload, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "failed to read all data from %s\n", TTP_SOCK_INPUT_FILE);
        free(payload);
        fclose(fp);
        return 1;
    }
    fclose(fp);
    fp = NULL;

    family = ttp_socket_family_detect();
    fd = socket(family, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        free(payload);
        return 1;
    }

    local.st_family = family;
    local.st_ifindex = if_nametoindex(argv[1]);
    local.st_vci = (unsigned char)atoi(argv[2]);
    if (!local.st_ifindex) {
        perror("if_nametoindex");
        free(payload);
        close(fd);
        return 1;
    }

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        free(payload);
        close(fd);
        return 1;
    }

    peer.st_family = family;
    peer.st_ifindex = local.st_ifindex;
    peer.st_vci = local.st_vci;
    if (ttp_parse_node(argv[3], peer.st_node) != 0) {
        fprintf(stderr, "invalid peer node '%s'\n", argv[3]);
        free(payload);
        close(fd);
        return 1;
    }

    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
        perror("connect");
        free(payload);
        close(fd);
        return 1;
    }

    n = send(fd, payload, (size_t)file_size, 0);
    if (n < 0) {
        perror("send");
        close(fd);
        free(payload);
        return 1;
    }
    if (n != file_size) {
        fprintf(stderr, "short send: %zd of %ld bytes\n", n, file_size);
        close(fd);
        free(payload);
        return 1;
    }

    free(payload);
    printf("sent %ld bytes from %s over family %d\n",
           file_size, TTP_SOCK_INPUT_FILE, family);
    if (do_shutdown_wr) {
        char byte;

        if (shutdown(fd, SHUT_WR) < 0) {
            perror("shutdown(SHUT_WR)");
            close(fd);
            return 1;
        }
        n = recv(fd, &byte, sizeof(byte), 0);
        if (n < 0) {
            perror("recv(after shutdown)");
            close(fd);
            return 1;
        }
        if (n != 0) {
            fprintf(stderr, "expected EOF after shutdown, got %zd bytes\n", n);
            close(fd);
            return 1;
        }
        printf("shutdown(SHUT_WR) completed, peer EOF observed\n");
    }
    if (linger_ms >= 0) {
        printf("waiting %d ms before close\n", linger_ms);
        (void)poll(NULL, 0, linger_ms);
    }
    close(fd);
    return 0;
}
