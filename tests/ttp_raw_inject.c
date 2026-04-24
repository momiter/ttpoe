// SPDX-License-Identifier: GPL-2.0
/*
 * Raw TTPoE packet injector for protocol/FSM branch testing.
 *
 * This tool sends handcrafted TTPoE Ethernet frames through AF_PACKET. It is
 * intentionally independent from /dev/noc_debug and AF_TTP sockets, so it can
 * exercise RX opcode branches with explicit TxID/RxID values.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TESLA_ETH_P_TTPOE 0x9ac6
#define TTP_TTH_LEN       20
#define TTP_TSH_LEN       8
#define TTP_HDR_LEN       18
#define TTP_OE_HDRS_LEN   (TTP_TTH_LEN + TTP_TSH_LEN + TTP_HDR_LEN)
#define TTP_MIN_FRAME_LEN 64
#define TTP_MAX_NOC_LEN   1024
#define TTP_MAX_FRAME_LEN (ETH_HLEN + TTP_OE_HDRS_LEN + TTP_MAX_NOC_LEN)

enum ttp_opcode {
    TTP_OPEN        = 0,
    TTP_OPEN_ACK    = 1,
    TTP_OPEN_NACK   = 2,
    TTP_CLOSE       = 3,
    TTP_CLOSE_ACK   = 4,
    TTP_CLOSE_NACK  = 5,
    TTP_PAYLOAD     = 6,
    TTP_ACK         = 7,
    TTP_NACK        = 8,
    TTP_NACK_FULL   = 9,
    TTP_NACK_NOLINK = 10,
};

struct inject_opts {
    const char *ifname;
    uint8_t src_mac[ETH_ALEN];
    uint8_t dst_mac[ETH_ALEN];
    bool src_mac_set;
    bool src_node_set;
    bool dst_mac_set;
    int opcode;
    int vc;
    uint32_t tx_id;
    uint32_t rx_id;
    uint8_t payload[TTP_MAX_NOC_LEN];
    size_t payload_len;
    int count;
    int interval_ms;
    bool dry_run;
};

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --dev IFACE --dst-mac MAC --opcode OP [options]\n"
        "\n"
        "Options:\n"
        "  --src-mac MAC          Spoof source MAC; default is IFACE MAC\n"
        "  --dst-node HEX24       Destination node, e.g. 000002; OUI is taken from src MAC\n"
        "  --src-node HEX24       Override TSH source node only\n"
        "  --dst-node-shim HEX24  Override TSH destination node only\n"
        "  --opcode OP            Name or number: open, open-ack, close, payload, ack,\n"
        "                         nack, nack-full, nack-nolink, close-ack, close-nack\n"
        "  --vc N                 VC id, default 0\n"
        "  --tx-id N              TTP TxID, default 0\n"
        "  --rx-id N              TTP RxID, default 0\n"
        "  --payload TEXT         NOC payload bytes for PAYLOAD or malformed control tests\n"
        "  --payload-hex HEX      Hex NOC payload, e.g. 010203aabb\n"
        "  --payload-file PATH    Read NOC payload from file, max 1024 bytes\n"
        "  --count N              Send N frames, default 1\n"
        "  --interval-ms N        Delay between frames, default 0\n"
        "  --dry-run              Print frame bytes without sending\n"
        "\n"
        "Examples:\n"
        "  sudo %s --dev ens33 --dst-node 000001 --opcode close --tx-id 5 --rx-id 1\n"
        "  sudo %s --dev ens33 --dst-node 000001 --opcode close-ack --rx-id 5\n"
        "  sudo %s --dev ens33 --dst-node 000001 --opcode payload --tx-id 2 --payload hello\n",
        prog, prog, prog, prog);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_mac(const char *s, uint8_t mac[ETH_ALEN])
{
    unsigned int b[ETH_ALEN];

    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != ETH_ALEN) {
        return -EINVAL;
    }
    for (int i = 0; i < ETH_ALEN; i++) {
        if (b[i] > 0xff) {
            return -EINVAL;
        }
        mac[i] = (uint8_t)b[i];
    }
    return 0;
}

static int parse_node24(const char *s, uint8_t node[3])
{
    size_t len = strlen(s);
    int hi, lo;

    if (len != 6) {
        return -EINVAL;
    }
    for (int i = 0; i < 3; i++) {
        hi = hexval(s[i * 2]);
        lo = hexval(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -EINVAL;
        }
        node[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int parse_hex_payload(const char *s, uint8_t *out, size_t *out_len)
{
    size_t len = strlen(s);

    if (len % 2 || len / 2 > TTP_MAX_NOC_LEN) {
        return -EINVAL;
    }
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hexval(s[i * 2]);
        int lo = hexval(s[i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return -EINVAL;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = len / 2;
    return 0;
}

static int read_payload_file(const char *path, uint8_t *out, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    size_t n;

    if (!fp) {
        return -errno;
    }
    n = fread(out, 1, TTP_MAX_NOC_LEN, fp);
    if (ferror(fp)) {
        int err = errno ? errno : EIO;
        fclose(fp);
        return -err;
    }
    if (!feof(fp)) {
        fclose(fp);
        return -EMSGSIZE;
    }
    fclose(fp);
    *out_len = n;
    return 0;
}

static int parse_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;
    int base = 10;

    if (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2)) {
        base = 16;
    }
    errno = 0;
    v = strtoul(s, &end, base);
    if (errno || !end || *end || v > UINT32_MAX) {
        return -EINVAL;
    }
    *out = (uint32_t)v;
    return 0;
}

static int parse_int(const char *s, int *out)
{
    uint32_t v;
    int rc = parse_u32(s, &v);

    if (rc) {
        return rc;
    }
    if (v > INT32_MAX) {
        return -EINVAL;
    }
    *out = (int)v;
    return 0;
}

static int parse_opcode(const char *s)
{
    struct {
        const char *name;
        int opcode;
    } names[] = {
        {"open", TTP_OPEN},
        {"open-ack", TTP_OPEN_ACK},
        {"open-nack", TTP_OPEN_NACK},
        {"close", TTP_CLOSE},
        {"close-ack", TTP_CLOSE_ACK},
        {"close-nack", TTP_CLOSE_NACK},
        {"payload", TTP_PAYLOAD},
        {"ack", TTP_ACK},
        {"nack", TTP_NACK},
        {"nack-full", TTP_NACK_FULL},
        {"nack-nolink", TTP_NACK_NOLINK},
        {"nolink", TTP_NACK_NOLINK},
    };
    int v;

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (!strcmp(s, names[i].name)) {
            return names[i].opcode;
        }
    }
    if (!parse_int(s, &v) && v >= 0 && v <= 63) {
        return v;
    }
    return -EINVAL;
}

static int get_if_info(const char *ifname, int *ifindex, uint8_t mac[ETH_ALEN])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    if (fd < 0) {
        return -errno;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }
    *ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
    return 0;
}

static void dump_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("%04zx:", i);
        }
        printf(" %02x", buf[i]);
        if (i % 16 == 15 || i + 1 == len) {
            putchar('\n');
        }
    }
}

static void put_be16(uint8_t *p, uint16_t v)
{
    uint16_t be = htons(v);

    memcpy(p, &be, sizeof(be));
}

static void put_be32(uint8_t *p, uint32_t v)
{
    uint32_t be = htonl(v);

    memcpy(p, &be, sizeof(be));
}

static size_t build_frame(const struct inject_opts *opts, uint8_t *frame)
{
    size_t noc_len = opts->payload_len;
    size_t wire_len = ETH_HLEN + TTP_OE_HDRS_LEN + noc_len;
    uint8_t *p = frame;
    uint16_t tth_total = (uint16_t)(TTP_OE_HDRS_LEN + noc_len);
    uint16_t tsh_len = (uint16_t)(TTP_TSH_LEN + TTP_HDR_LEN + noc_len);
    uint8_t src_node[3] = { opts->src_mac[3], opts->src_mac[4], opts->src_mac[5] };
    uint8_t dst_node[3] = { opts->dst_mac[3], opts->dst_mac[4], opts->dst_mac[5] };

    memset(frame, 0, TTP_MAX_FRAME_LEN);

    memcpy(p, opts->dst_mac, ETH_ALEN);
    p += ETH_ALEN;
    memcpy(p, opts->src_mac, ETH_ALEN);
    p += ETH_ALEN;
    put_be16(p, TESLA_ETH_P_TTPOE);
    p += sizeof(uint16_t);

    p[0] = 0x05; /* TTH: tthl=5, version/subtype=0 */
    p[1] = 0x00; /* raw ethernet, not gateway */
    put_be16(p + 2, tth_total);
    p += TTP_TTH_LEN;

    memcpy(p, src_node, sizeof(src_node));
    p += sizeof(src_node);
    memcpy(p, dst_node, sizeof(dst_node));
    p += sizeof(dst_node);
    put_be16(p, tsh_len);
    p += sizeof(uint16_t);

    p[0] = (uint8_t)(opts->opcode & 0x3f);
    p[1] = (uint8_t)(opts->vc & 0xff);
    p[2] = 0; /* legacy conn_tx */
    p[3] = 0; /* legacy conn_rx */
    put_be16(p + 4, 0); /* epoch */
    p[6] = 0; /* congestion */
    put_be16(p + 7, 0); /* reserved/version bits */
    p[9] = 0; /* extension count/type */
    put_be32(p + 10, opts->tx_id);
    put_be32(p + 14, opts->rx_id);
    p += TTP_HDR_LEN;

    if (noc_len) {
        memcpy(p, opts->payload, noc_len);
    }

    if (wire_len < TTP_MIN_FRAME_LEN) {
        wire_len = TTP_MIN_FRAME_LEN;
    }
    return wire_len;
}

static int send_frame(const struct inject_opts *opts, int ifindex,
                      const uint8_t *frame, size_t len)
{
    int fd;
    struct sockaddr_ll sll;
    ssize_t sent;

    fd = socket(AF_PACKET, SOCK_RAW, htons(TESLA_ETH_P_TTPOE));
    if (fd < 0) {
        return -errno;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(TESLA_ETH_P_TTPOE);
    sll.sll_ifindex = ifindex;
    sll.sll_halen = ETH_ALEN;
    memcpy(sll.sll_addr, opts->dst_mac, ETH_ALEN);

    sent = sendto(fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll));
    if (sent < 0) {
        int err = errno;
        close(fd);
        return -err;
    }
    close(fd);
    return sent == (ssize_t)len ? 0 : -EIO;
}

static void sleep_ms(int ms)
{
    struct timespec ts;

    if (ms <= 0) {
        return;
    }
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

int main(int argc, char **argv)
{
    struct inject_opts opts = {
        .opcode = -1,
        .vc = 0,
        .count = 1,
    };
    uint8_t frame[TTP_MAX_FRAME_LEN];
    uint8_t node[3];
    uint8_t if_mac[ETH_ALEN];
    int ifindex = 0;
    int rc;
    size_t frame_len;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dev") && i + 1 < argc) {
            opts.ifname = argv[++i];
        } else if (!strcmp(argv[i], "--src-mac") && i + 1 < argc) {
            rc = parse_mac(argv[++i], opts.src_mac);
            if (rc) {
                fprintf(stderr, "invalid --src-mac\n");
                return 2;
            }
            opts.src_mac_set = true;
        } else if (!strcmp(argv[i], "--dst-mac") && i + 1 < argc) {
            rc = parse_mac(argv[++i], opts.dst_mac);
            if (rc) {
                fprintf(stderr, "invalid --dst-mac\n");
                return 2;
            }
            opts.dst_mac_set = true;
        } else if (!strcmp(argv[i], "--dst-node") && i + 1 < argc) {
            rc = parse_node24(argv[++i], node);
            if (rc) {
                fprintf(stderr, "invalid --dst-node\n");
                return 2;
            }
            opts.dst_mac[3] = node[0];
            opts.dst_mac[4] = node[1];
            opts.dst_mac[5] = node[2];
            opts.dst_mac_set = true;
        } else if (!strcmp(argv[i], "--src-node") && i + 1 < argc) {
            rc = parse_node24(argv[++i], node);
            if (rc) {
                fprintf(stderr, "invalid --src-node\n");
                return 2;
            }
            opts.src_mac[3] = node[0];
            opts.src_mac[4] = node[1];
            opts.src_mac[5] = node[2];
            opts.src_node_set = true;
        } else if (!strcmp(argv[i], "--dst-node-shim") && i + 1 < argc) {
            rc = parse_node24(argv[++i], node);
            if (rc) {
                fprintf(stderr, "invalid --dst-node-shim\n");
                return 2;
            }
            opts.dst_mac[3] = node[0];
            opts.dst_mac[4] = node[1];
            opts.dst_mac[5] = node[2];
            opts.dst_mac_set = true;
        } else if (!strcmp(argv[i], "--opcode") && i + 1 < argc) {
            opts.opcode = parse_opcode(argv[++i]);
            if (opts.opcode < 0) {
                fprintf(stderr, "invalid --opcode\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--vc") && i + 1 < argc) {
            rc = parse_int(argv[++i], &opts.vc);
            if (rc || opts.vc < 0 || opts.vc > 255) {
                fprintf(stderr, "invalid --vc\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--tx-id") && i + 1 < argc) {
            rc = parse_u32(argv[++i], &opts.tx_id);
            if (rc) {
                fprintf(stderr, "invalid --tx-id\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--rx-id") && i + 1 < argc) {
            rc = parse_u32(argv[++i], &opts.rx_id);
            if (rc) {
                fprintf(stderr, "invalid --rx-id\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--payload") && i + 1 < argc) {
            const char *payload = argv[++i];
            size_t len = strlen(payload);

            if (len > TTP_MAX_NOC_LEN) {
                fprintf(stderr, "payload too large, max %d bytes\n", TTP_MAX_NOC_LEN);
                return 2;
            }
            memcpy(opts.payload, payload, len);
            opts.payload_len = len;
        } else if (!strcmp(argv[i], "--payload-hex") && i + 1 < argc) {
            rc = parse_hex_payload(argv[++i], opts.payload, &opts.payload_len);
            if (rc) {
                fprintf(stderr, "invalid --payload-hex\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--payload-file") && i + 1 < argc) {
            rc = read_payload_file(argv[++i], opts.payload, &opts.payload_len);
            if (rc) {
                fprintf(stderr, "failed to read payload file: %s\n", strerror(-rc));
                return 2;
            }
        } else if (!strcmp(argv[i], "--count") && i + 1 < argc) {
            rc = parse_int(argv[++i], &opts.count);
            if (rc || opts.count < 1) {
                fprintf(stderr, "invalid --count\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc) {
            rc = parse_int(argv[++i], &opts.interval_ms);
            if (rc || opts.interval_ms < 0) {
                fprintf(stderr, "invalid --interval-ms\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--dry-run")) {
            opts.dry_run = true;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!opts.ifname || opts.opcode < 0) {
        usage(argv[0]);
        return 2;
    }

    rc = get_if_info(opts.ifname, &ifindex, if_mac);
    if (rc) {
        fprintf(stderr, "failed to query interface %s: %s\n", opts.ifname, strerror(-rc));
        return 1;
    }
    if (!opts.src_mac_set) {
        uint8_t saved_node[3] = { opts.src_mac[3], opts.src_mac[4], opts.src_mac[5] };

        memcpy(opts.src_mac, if_mac, ETH_ALEN);
        if (opts.src_node_set) {
            opts.src_mac[3] = saved_node[0];
            opts.src_mac[4] = saved_node[1];
            opts.src_mac[5] = saved_node[2];
        }
    }

    if (opts.src_mac_set && opts.src_node_set) {
        /* --src-node is allowed to refine --src-mac's low 24 bits. */
    }

    if (!opts.dst_mac_set) {
        fprintf(stderr, "--dst-mac or --dst-node is required\n");
        return 2;
    }
    if (!opts.dst_mac[0] && !opts.dst_mac[1] && !opts.dst_mac[2]) {
        opts.dst_mac[0] = opts.src_mac[0];
        opts.dst_mac[1] = opts.src_mac[1];
        opts.dst_mac[2] = opts.src_mac[2];
    }

    frame_len = build_frame(&opts, frame);

    printf("dev=%s ifindex=%d opcode=%d vc=%d tx=%u rx=%u noc_len=%zu frame_len=%zu\n",
           opts.ifname, ifindex, opts.opcode, opts.vc, opts.tx_id, opts.rx_id,
           opts.payload_len, frame_len);
    printf("src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
           opts.src_mac[0], opts.src_mac[1], opts.src_mac[2],
           opts.src_mac[3], opts.src_mac[4], opts.src_mac[5],
           opts.dst_mac[0], opts.dst_mac[1], opts.dst_mac[2],
           opts.dst_mac[3], opts.dst_mac[4], opts.dst_mac[5]);

    if (opts.dry_run) {
        dump_hex(frame, frame_len);
        return 0;
    }

    for (int i = 0; i < opts.count; i++) {
        rc = send_frame(&opts, ifindex, frame, frame_len);
        if (rc) {
            fprintf(stderr, "send failed: %s\n", strerror(-rc));
            return 1;
        }
        if (i + 1 < opts.count) {
            sleep_ms(opts.interval_ms);
        }
    }

    return 0;
}
