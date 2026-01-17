//-------#LLM Generated code begins ------------
#include "cshark_p2.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <ctype.h>
#include <unistd.h>

/* global (defined in cshark_p2.c) */
int cshark_current_dlt = -1;

/* Helpers */
void format_mac(const uint8_t *mac, char *dst, size_t dstsz) {
    if (!mac || !dst) return;
    snprintf(dst, dstsz, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static const char *ip_proto_name(uint8_t p) {
    switch (p) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default: return "Unknown";
    }
}
static const char *port_common_name(uint16_t port) {
    switch (port) {
        case 53: return "DNS";
        case 80: return "HTTP";
        case 443: return "HTTPS";
        default: return NULL;
    }
}

/* --- L7 hex+ascii dump --- */
static void hexdump_hex_ascii(const uint8_t *data, uint32_t len, uint32_t max_bytes) {
    uint32_t to_show = (len < max_bytes) ? len : max_bytes;
    if (to_show == 0) { printf("(no payload)\n"); return; }
    for (uint32_t i=0;i<to_show;i+=16) {
        uint32_t line_len = (to_show - i >= 16) ? 16 : (to_show - i);
        for (uint32_t j=0;j<line_len;++j) printf("%02X ", data[i+j]);
        if (line_len < 16) for (uint32_t p=0;p<16-line_len;++p) printf("   ");
        printf(" ");
        for (uint32_t j=0;j<line_len;++j) {
            uint8_t c = data[i+j];
            putchar((c >= 32 && c <= 126) ? (char)c : '.');
        }
        printf("\n");
    }
}

/* Identify app by ports and show L7 */
static void handle_payload_and_print_app(uint16_t src_port, uint16_t dst_port,
                                         const uint8_t *payload, uint32_t payload_len) {
    const char *app = "Unknown";
    if (src_port == 80 || dst_port == 80) app = "HTTP";
    else if (src_port == 443 || dst_port == 443) app = "HTTPS/TLS";
    else if (src_port == 53 || dst_port == 53) app = "DNS";

    printf("L7 (Payload): Identified as %s on ports %u/%u - %u bytes\n",
           app, src_port, dst_port, (unsigned)payload_len);

    uint32_t to_dump = (payload_len < 64) ? payload_len : 64;
    if (to_dump > 0) {
        printf("Data (first %u bytes):\n", to_dump);
        hexdump_hex_ascii(payload, payload_len, to_dump);
    } else {
        printf("Data (first 0 bytes): (no payload)\n");
    }
}

/* --- L4 --- decode tcp/udp from raw bytes (ptr points to start of transport header) */
static void decode_tcp(const uint8_t *ptr, uint32_t len) {
    if (len < 20) { printf("L4 (TCP): packet too short for TCP header (avail=%u)\n", len); return; }
    uint16_t src_port = (ptr[0]<<8) | ptr[1];
    uint16_t dst_port = (ptr[2]<<8) | ptr[3];
    uint32_t seq = (ptr[4]<<24)|(ptr[5]<<16)|(ptr[6]<<8)|ptr[7];
    uint32_t ack = (ptr[8]<<24)|(ptr[9]<<16)|(ptr[10]<<8)|ptr[11];
    uint8_t data_offset = (ptr[12] >> 4) & 0x0F;
    uint32_t header_len = (data_offset>0) ? data_offset*4 : 20;
    if (len < header_len) { printf("L4 (TCP): truncated TCP header need=%u have=%u\n", header_len, len); return; }
    uint8_t flags = ptr[13];
    uint16_t window = (ptr[14]<<8)|ptr[15];
    uint16_t checksum = (ptr[16]<<8)|ptr[17];

    const char *srccn = port_common_name(src_port);
    const char *dstcn = port_common_name(dst_port);

    printf("L4 (TCP): Src Port: %u", src_port);
    if (srccn) printf(" (%s)", srccn);
    printf(" | Dst Port: %u", dst_port);
    if (dstcn) printf(" (%s)", dstcn);
    printf(" | Seq: %u | Ack: %u\n", seq, ack);

    printf("          Flags:");
    if (flags & 0x01) printf(" [FIN]");
    if (flags & 0x02) printf(" [SYN]");
    if (flags & 0x04) printf(" [RST]");
    if (flags & 0x08) printf(" [PSH]");
    if (flags & 0x10) printf(" [ACK]");
    if (flags & 0x20) printf(" [URG]");
    if (flags & 0x40) printf(" [ECE]");
    if (flags & 0x80) printf(" [CWR]");
    if (!(flags & 0xFF)) printf(" [none]");
    printf(" | Window: %u | Checksum: 0x%04X | Header Length: %u bytes\n",
           window, checksum, header_len);

    uint32_t payload_len = (len > header_len) ? (len - header_len) : 0;
    const uint8_t *payload = ptr + header_len;
    handle_payload_and_print_app(src_port, dst_port, payload, payload_len);
}

static void decode_udp(const uint8_t *ptr, uint32_t len) {
    if (len < 8) { printf("L4 (UDP): packet too short for UDP header (avail=%u)\n", len); return; }
    uint16_t src_port = (ptr[0]<<8)|ptr[1];
    uint16_t dst_port = (ptr[2]<<8)|ptr[3];
    uint16_t ulen = (ptr[4]<<8)|ptr[5];
    uint16_t checksum = (ptr[6]<<8)|ptr[7];
    const char *srccn = port_common_name(src_port);
    const char *dstcn = port_common_name(dst_port);
    printf("L4 (UDP): Src Port: %u", src_port);
    if (srccn) printf(" (%s)", srccn);
    printf(" | Dst Port: %u", dst_port);
    if (dstcn) printf(" (%s)", dstcn);
    printf(" | Length: %u | Checksum: 0x%04X\n", ulen, checksum);

    uint32_t payload_len = (len > 8) ? len - 8 : 0;
    const uint8_t *payload = ptr + 8;
    handle_payload_and_print_app(src_port, dst_port, payload, payload_len);
}

static void decode_transport(uint8_t proto, const uint8_t *ptr, uint32_t len) {
    if (!ptr) return;
    if (proto == IPPROTO_TCP) decode_tcp(ptr, len);
    else if (proto == IPPROTO_UDP) decode_udp(ptr, len);
    else {
        printf("L4: Unsupported transport protocol %u. First bytes:\n", proto);
        uint32_t to_print = len < 16 ? len : 16;
        for (uint32_t i=0;i<to_print;++i) printf("%02X ", ptr[i]);
        if (to_print == 0) printf("(no data)");
        printf("\n");
    }
}

/* ---------------- L3 Decoders ---------------- */

/* IPv4 decoder using struct iphdr */
void decode_ipv4(const uint8_t *ip_ptr, uint32_t avail_len) {
    if (avail_len < 20) { printf("L3 (IPv4): packet too short for IPv4 header (avail=%u)\n", avail_len); return; }
    const struct iphdr *ip = (const struct iphdr *)ip_ptr;
    uint8_t version = ip->version;
    if (version != 4) { printf("L3 (IPv4): invalid version %u\n", version); return; }
    uint8_t ihl = ip->ihl;
    uint32_t header_len = (ihl>0)? ihl*4:20;
    if (avail_len < header_len) { printf("L3 (IPv4): truncated header\n"); return; }
    uint16_t total_len = ntohs(ip->tot_len);
    uint16_t id = ntohs(ip->id);
    uint8_t ttl = ip->ttl;
    uint8_t proto = ip->protocol;
    uint16_t frag_off_net = ntohs(ip->frag_off);
    int df = (frag_off_net & 0x4000) ? 1 : 0;
    int mf = (frag_off_net & 0x2000) ? 1 : 0;
    uint16_t frag_offset = frag_off_net & 0x1FFF;

    char src[INET_ADDRSTRLEN]={0}, dst[INET_ADDRSTRLEN]={0};
    struct in_addr a;
    a.s_addr = ip->saddr; inet_ntop(AF_INET, &a, src, sizeof(src));
    a.s_addr = ip->daddr; inet_ntop(AF_INET, &a, dst, sizeof(dst));

    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%u) |\n",
           src, dst, ip_proto_name(proto), proto);
    printf("TTL: %u\n", ttl);
    printf("ID: 0x%04X | Total Length: %u | Header Length: %u bytes\n",
           id, total_len, header_len);
    printf("Flags:");
    if (df) printf(" [DF]");
    if (mf) printf(" [MF]");
    if (!df && !mf) printf(" [none]");
    printf(" | Fragment Offset: %u\n", frag_offset);

    if (avail_len > header_len) {
        const uint8_t *transport = ip_ptr + header_len;
        uint32_t transport_len = avail_len - header_len;
        decode_transport(proto, transport, transport_len);
    } else {
        printf("L4: No transport data (packet truncated or header-only)\n");
    }
}

/* IPv6 decoder */
void decode_ipv6(const uint8_t *ip6_ptr, uint32_t avail_len) {
    if (avail_len < sizeof(struct ip6_hdr)) { printf("L3 (IPv6): packet too short (avail=%u)\n", avail_len); return; }
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip6_ptr;
    uint32_t vtf = ntohl(ip6->ip6_flow);
    uint8_t version = (vtf >> 28) & 0x0F;
    if (version != 6) { printf("L3 (IPv6): invalid version %u\n", version); return; }
    uint8_t traffic_class = (vtf >> 20) & 0xFF;
    uint32_t flow_label = vtf & 0x000FFFFF;
    uint16_t payload_len = ntohs(ip6->ip6_plen);
    uint8_t next_hdr = ip6->ip6_nxt;
    uint8_t hop_limit = ip6->ip6_hlim;

    char src[INET6_ADDRSTRLEN]={0}, dst[INET6_ADDRSTRLEN]={0};
    inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

    printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src, dst);
    printf("Next Header: %s (%u) | Hop Limit: %u | Traffic Class: %u | Flow Label: 0x%05X | Payload Length: %u\n",
           ip_proto_name(next_hdr), next_hdr, hop_limit, traffic_class, flow_label, payload_len);

    if (avail_len > 40) {
        const uint8_t *transport = ip6_ptr + 40;
        uint32_t transport_len = avail_len - 40;
        decode_transport(next_hdr, transport, transport_len);
    } else {
        printf("L4: No transport data (packet truncated or no payload)\n");
    }
}

/* ARP decoder */
void decode_arp(const uint8_t *arp_ptr, uint32_t avail_len) {
    if (avail_len < sizeof(struct arphdr)) { printf("L3 (ARP): packet too short\n"); return; }
    const struct arphdr *ar = (const struct arphdr *)arp_ptr;
    uint16_t htype = ntohs(ar->ar_hrd);
    uint16_t ptype = ntohs(ar->ar_pro);
    uint8_t hlen = ar->ar_hln;
    uint8_t plen = ar->ar_pln;
    uint16_t oper = ntohs(ar->ar_op);

    size_t needed = sizeof(struct arphdr) + (size_t)hlen + plen + hlen + plen;
    if (avail_len < needed) { printf("L3 (ARP): truncated (avail=%u needed=%zu)\n", avail_len, needed); return; }

    const uint8_t *p = arp_ptr + sizeof(struct arphdr);
    const uint8_t *sha = p; p += hlen;
    const uint8_t *spa = p; p += plen;
    const uint8_t *tha = p; p += hlen;
    const uint8_t *tpa = p; p += plen;

    char sha_s[64]={0}, tha_s[64]={0}, spa_s[64]={0}, tpa_s[64]={0};
    if (hlen==6) format_mac(sha, sha_s, sizeof(sha_s));
    else snprintf(sha_s, sizeof(sha_s),"(%u bytes)", hlen);
    if (hlen==6) format_mac(tha, tha_s, sizeof(tha_s));
    else snprintf(tha_s, sizeof(tha_s),"(%u bytes)", hlen);

    if (plen == 4) {
        struct in_addr a;
        memcpy(&a.s_addr, spa, 4); inet_ntop(AF_INET, &a, spa_s, sizeof(spa_s));
        memcpy(&a.s_addr, tpa, 4); inet_ntop(AF_INET, &a, tpa_s, sizeof(tpa_s));
    } else if (plen == 16) {
        inet_ntop(AF_INET6, spa, spa_s, sizeof(spa_s));
        inet_ntop(AF_INET6, tpa, tpa_s, sizeof(tpa_s));
    } else {
        snprintf(spa_s, sizeof(spa_s),"(%u bytes)", plen);
        snprintf(tpa_s, sizeof(tpa_s),"(%u bytes)", plen);
    }

    const char *op_name = (oper==1)?"Request":(oper==2)?"Reply":"Unknown";
    printf("L3 (ARP): Operation: %s (%u) | Sender IP: %s | Target IP: %s\n", op_name, oper, spa_s, tpa_s);
    printf("Sender MAC: %s | Target MAC: %s\n", sha_s, tha_s);
    printf("HW Type: %u | Proto Type: 0x%04X | HW Len: %u | Proto Len: %u\n", htype, ptype, hlen, plen);
}

//-------#LLM Generated code ends ------------
