#include <stdio.h>
#include <string.h>

#include "../include/ttp_socket.h"

#include "ttp_sock_common.h"

int ttp_socket_family_detect(void)
{
    FILE *fp;
    int family = AF_TTP;

    fp = fopen("/sys/module/modttpoe/parameters/socket_family", "r");
    if (!fp) {
        return family;
    }
    if (fscanf(fp, "%d", &family) != 1) {
        family = AF_TTP;
    }
    fclose(fp);
    return family;
}

int ttp_parse_node(const char *text, unsigned char node[3])
{
    unsigned int value;

    if (strchr(text, ':')) {
        unsigned int b0, b1, b2;

        if (sscanf(text, "%x:%x:%x", &b0, &b1, &b2) != 3) {
            return -1;
        }
        node[0] = (unsigned char)b0;
        node[1] = (unsigned char)b1;
        node[2] = (unsigned char)b2;
        return 0;
    }

    if (sscanf(text, "%x", &value) != 1 || value > 0xffffffU) {
        return -1;
    }

    node[0] = (value >> 16) & 0xff;
    node[1] = (value >> 8) & 0xff;
    node[2] = value & 0xff;
    return 0;
}
