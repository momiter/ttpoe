#include <net/if.h>
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

static int read_input_file(char *buffer, size_t *len)
{
    FILE *fp;
    long file_size;
    size_t nread;

    fp = fopen(TTP_SOCK_INPUT_FILE, "rb");
    if (!fp) {
        perror("fopen(test.txt)");
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek(test.txt)");
        fclose(fp);
        return -1;
    }

    file_size = ftell(fp);
    if (file_size < 0) {
        perror("ftell(test.txt)");
        fclose(fp);
        return -1;
    }
    if (file_size == 0) {
        fprintf(stderr, "%s is empty\n", TTP_SOCK_INPUT_FILE);
        fclose(fp);
        return -1;
    }
    if (file_size > TTP_SOCK_MAX_PAYLOAD) {
        fprintf(stderr, "%s is too large: %ld bytes (max %d)\n",
                TTP_SOCK_INPUT_FILE, file_size, TTP_SOCK_MAX_PAYLOAD);
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek(test.txt)");
        fclose(fp);
        return -1;
    }

    nread = fread(buffer, 1, (size_t)file_size, fp);
    if (nread != (size_t)file_size) {
        fprintf(stderr, "failed to read all data from %s\n", TTP_SOCK_INPUT_FILE);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *len = nread;
    return 0;
}

int main(int argc, char **argv)
{
    struct sockaddr_ttp local = {0};
    struct sockaddr_ttp peer = {0};
    char payload[TTP_SOCK_MAX_PAYLOAD];
    size_t payload_len = 0;
    int family;
    int fd;
    int linger_ms = -1;
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

    if (read_input_file(payload, &payload_len) != 0) {
        return 1;
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

    n = send(fd, payload, payload_len, 0);
    if (n < 0) {
        perror("send");
        close(fd);
        return 1;
    }

    printf("sent %zd bytes from %s over family %d\n", n, TTP_SOCK_INPUT_FILE, family);
    if (linger_ms >= 0) {
        printf("waiting %d ms before close\n", linger_ms);
        (void)poll(NULL, 0, linger_ms);
    }
    close(fd);
    return 0;
}
