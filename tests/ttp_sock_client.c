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
#define TTP_SOCK_MAX_PAYLOAD 1008
#define TTP_FILE_MAGIC "TTPF"

struct ttp_file_header {
    char magic[4];
    unsigned int file_size_be;
};

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
    struct ttp_file_header header;
    char payload[TTP_SOCK_MAX_PAYLOAD];
    int family;
    int fd;
    int linger_ms = -1;
    FILE *fp = NULL;
    long file_size;
    size_t chunk_len;
    size_t total_sent = 0;
    ssize_t n;

    if (argc != 4 && argc != 5) {
        fprintf(stderr,
                "usage: %s <ifname> <vci> <peer-node> [linger-ms]\n",
                argv[0]);
        fprintf(stderr, "note: send data is read from %s\n", TTP_SOCK_INPUT_FILE);
        return 2;
    }

    if (argc == 5) {
        char *end = NULL;

        linger_ms = (int)strtol(argv[4], &end, 0);
        if (!end || *end != '\0' || linger_ms < 0) {
            fprintf(stderr, "invalid linger-ms '%s'\n", argv[4]);
            return 2;
        }
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
    if ((unsigned long)file_size > 0xffffffffUL) {
        fprintf(stderr, "%s is too large for test header: %ld bytes\n",
                TTP_SOCK_INPUT_FILE, file_size);
        fclose(fp);
        return 1;
    }

    family = ttp_socket_family_detect();
    fd = socket(family, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        fclose(fp);
        return 1;
    }

    local.st_family = family;
    local.st_ifindex = if_nametoindex(argv[1]);
    local.st_vci = (unsigned char)atoi(argv[2]);
    if (!local.st_ifindex) {
        perror("if_nametoindex");
        fclose(fp);
        close(fd);
        return 1;
    }

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        fclose(fp);
        close(fd);
        return 1;
    }

    peer.st_family = family;
    peer.st_ifindex = local.st_ifindex;
    peer.st_vci = local.st_vci;
    if (ttp_parse_node(argv[3], peer.st_node) != 0) {
        fprintf(stderr, "invalid peer node '%s'\n", argv[3]);
        fclose(fp);
        close(fd);
        return 1;
    }

    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
        perror("connect");
        fclose(fp);
        close(fd);
        return 1;
    }

    memcpy(header.magic, TTP_FILE_MAGIC, sizeof(header.magic));
    header.file_size_be = htonl((unsigned int)file_size);

    n = send(fd, &header, sizeof(header), 0);
    if (n < 0) {
        perror("send(header)");
        close(fd);
        fclose(fp);
        return 1;
    }
    if ((size_t)n != sizeof(header)) {
        fprintf(stderr, "short send for header: %zd bytes\n", n);
        close(fd);
        fclose(fp);
        return 1;
    }

    while ((chunk_len = fread(payload, 1, sizeof(payload), fp)) > 0) {
        n = send(fd, payload, chunk_len, 0);
        if (n < 0) {
            perror("send(payload)");
            close(fd);
            fclose(fp);
            return 1;
        }
        if ((size_t)n != chunk_len) {
            fprintf(stderr, "short send for payload chunk: %zd of %zu bytes\n",
                    n, chunk_len);
            close(fd);
            fclose(fp);
            return 1;
        }
        total_sent += chunk_len;
    }
    if (ferror(fp)) {
        fprintf(stderr, "failed while reading data from %s\n", TTP_SOCK_INPUT_FILE);
        close(fd);
        fclose(fp);
        return 1;
    }

    fclose(fp);
    printf("sent %zu bytes from %s over family %d\n",
           total_sent, TTP_SOCK_INPUT_FILE, family);
    if (linger_ms >= 0) {
        printf("waiting %d ms before close\n", linger_ms);
        (void)poll(NULL, 0, linger_ms);
    }
    close(fd);
    return 0;
}
