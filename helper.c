//-------#LLM Generated code begins ------------

#include "cshark_p2.h"
#include "helper.h"
#include <net/ethernet.h> /* for ETHERTYPE_* */
#include <arpa/inet.h>    /* ntohs */
#include <string.h>
#include <stdint.h>

static const char *ethertype_to_name(uint16_t ethertype) {
    switch (ethertype) {
        case ETHERTYPE_IP: return "IPv4";
        case ETHERTYPE_ARP: return "ARP";
        case ETHERTYPE_IPV6: return "IPv6";
        default: return "Unknown";
    }
}

/* Top-level: try to handle Ethernet frames, SLL, or direct IP */
void decode_ethernet_and_ip_layer_with_dlt(const uint8_t *data, uint32_t len, int dlt) {
    /* Minimal SLL header definition (Linux cooked capture) */
    struct sll_header {
        uint16_t sll_pkttype;
        uint16_t sll_hatype;
        uint16_t sll_halen;
        uint8_t  sll_addr[8];
        uint16_t sll_protocol;
    } __attribute__((packed));

    /* Helper to print a pseudo-mac from sll_addr (use up to 6 bytes) */
    char sll_addr_str[32];

    /* Local simple function to format sll addr into sll_addr_str */
    {
        sll_addr_str[0] = '\0';
        /* we'll fill later when needed */
    }

    /* If datalink unknown (-1): try to auto-detect IP version first */
    if (dlt == -1) {
        if (len >= 1) {
            uint8_t first = data[0];
            uint8_t ver = first >> 4;
            if (ver == 4) { decode_ipv4(data, len); return; }
            if (ver == 6) { decode_ipv6(data, len); return; }
        }
        /* else fall through to attempt Ethernet parsing */
    }

    /* Handle Linux cooked capture (SLL) */
    if (dlt == DLT_LINUX_SLL) {
        if (len < sizeof(struct sll_header)) {
            printf("L2 (SLL): frame too short for SLL header (len=%u)\n", len);
            return;
        }
        const struct sll_header *sll = (const struct sll_header *)data;
        uint16_t proto = ntohs(sll->sll_protocol);

        /* format the sll_addr as best-effort pseudo-MAC (use up to 6 bytes) */
        {
            int ha = sll->sll_halen;
            if (ha > 8) ha = 8;
            char tmp[64];
            tmp[0] = '\0';
            for (int i = 0; i < ha && i < 6; ++i) {
                char part[8];
                if (i) strcat(tmp, ":");
                snprintf(part, sizeof(part), "%02X", sll->sll_addr[i]);
                strcat(tmp, part);
            }
            if (ha == 0) snprintf(tmp, sizeof(tmp), "(none)");
            snprintf(sll_addr_str, sizeof(sll_addr_str), "%s", tmp);
        }

        printf("L2 (SLL): Proto: 0x%04X | Addr: %s | Hatype: %u | PakType: %u\n",
               proto, sll_addr_str, ntohs(sll->sll_hatype), ntohs(sll->sll_pkttype));

        const uint8_t *payload = data + sizeof(struct sll_header);
        uint32_t payload_len = (len > sizeof(struct sll_header)) ? (len - sizeof(struct sll_header)) : 0;

        if (proto == ETHERTYPE_IP) {
            decode_ipv4(payload, payload_len);
            return;
        } else if (proto == ETHERTYPE_IPV6) {
            decode_ipv6(payload, payload_len);
            return;
        } else if (proto == ETHERTYPE_ARP) {
            decode_arp(payload, payload_len);
            return;
        } else {
            /* fallback: maybe payload is raw IP even if proto unknown */
            if (payload_len >= 1) {
                uint8_t ver = payload[0] >> 4;
                if (ver == 4) { decode_ipv4(payload, payload_len); return; }
                if (ver == 6) { decode_ipv6(payload, payload_len); return; }
            }
            printf("L3: Unknown or unsupported SLL proto (0x%04X). First payload bytes:\n", proto);
            uint32_t to_print = payload_len < 16 ? payload_len : 16;
            for (uint32_t i = 0; i < to_print; ++i) printf("%02X ", payload[i]);
            if (to_print == 0) printf("(no payload)");
            printf("\n");
            return;
        }
    }

    /* Handle standard Ethernet */
    if (dlt == DLT_EN10MB || dlt == -1) {
        if (len >= sizeof(struct ether_header)) {
            const struct ether_header *eth = (const struct ether_header *)data;
            char src[32] = {0}, dst[32] = {0};
            format_mac(eth->ether_shost, src, sizeof(src));
            format_mac(eth->ether_dhost, dst, sizeof(dst));
            
            uint16_t ethertype = ntohs(eth->ether_type);

            const uint8_t *payload = data + sizeof(struct ether_header);
            uint32_t payload_len = (len > sizeof(struct ether_header)) ? (len - sizeof(struct ether_header)) : 0;

            /* Heuristic fallback: if ethertype==0 or payload looks like IP at frame start,
            prefer treating as raw IP rather than trusting an invalid ethertype or MACs. */
            int payload_is_ip = 0;
            if (payload_len >= 1) {
                uint8_t ver = payload[0] >> 4;
                if (ver == 4 || ver == 6) payload_is_ip = 1;
            }

            /* If ethertype is zero (0x0000 — seen on some loopback/virtual setups) OR
            payload looks like IP but ethertype is weird, then decode as raw IP payload. */
            if (ethertype == 0x0000 || (payload_is_ip && (ethertype != ETHERTYPE_IP && ethertype != ETHERTYPE_IPV6 && ethertype != ETHERTYPE_ARP))) {
                /* print a smaller L2 summary indicating fallback */
                printf("L2 (Ethernet fallback): Dst MAC: %s | Src MAC: %s | Ethertype: 0x%04X (interpreting payload as IP)\n",
                    dst, src, ethertype);
                if (payload_len >= 1) {
                    uint8_t ver = payload[0] >> 4;
                    if (ver == 4) { decode_ipv4(payload, payload_len); return; }
                    if (ver == 6) { decode_ipv6(payload, payload_len); return; }
                }
                /* if not IP, fall through to regular logic */
            }

            printf("L2 (Ethernet): Dst MAC: %s | Src MAC: %s | Ethertype: %s (0x%04X)\n",
                   dst, src, ethertype_to_name(ethertype), ethertype);

            //const uint8_t *payload = data + sizeof(struct ether_header);
            //uint32_t payload_len = (len > sizeof(struct ether_header)) ? (len - sizeof(struct ether_header)) : 0;

            switch (ethertype) {
                case ETHERTYPE_IP:   decode_ipv4(payload, payload_len); return;
                case ETHERTYPE_IPV6: decode_ipv6(payload, payload_len); return;
                case ETHERTYPE_ARP:  decode_arp(payload, payload_len); return;
                default:
                    /* If ethertype is 0x0000 or unknown, try payload auto-detect too */
                    if (payload_len >= 1) {
                        uint8_t ver = payload[0] >> 4;
                        if (ver == 4) { decode_ipv4(payload, payload_len); return; }
                        if (ver == 6) { decode_ipv6(payload, payload_len); return; }
                    }
                    printf("L3: Unknown or unsupported EtherType (0x%04X). First payload bytes:\n", ethertype);
                    {
                        uint32_t to_print = payload_len < 16 ? payload_len : 16;
                        for (uint32_t i = 0; i < to_print; ++i) printf("%02X ", payload[i]);
                        if (to_print == 0) printf("(no payload)");
                        printf("\n");
                    }
                    return;
            }
        } else {
            /* Couldn't parse Ethernet header; if DLT was -1 we already tried raw-IP above, otherwise print bytes */
            if (dlt != -1) {
                /* if DLT was explicitly EN10MB but len too small, fall through to fallback below */
                ;
            } else {
                /* already tried raw-IP earlier; fall through */
                ;
            }
        }
    }

    /* Final fallback: try raw-IP autodetect on the frame start */
    if (len >= 1) {
        uint8_t ver = data[0] >> 4;
        if (ver == 4) { decode_ipv4(data, len); return; }
        if (ver == 6) { decode_ipv6(data, len); return; }
    }

    /* Nothing matched: print a short raw preview */
    printf("L2: Unable to parse frame (len=%u). First bytes:\n", len);
    uint32_t to_print = len < 16 ? len : 16;
    for (uint32_t i = 0; i < to_print; ++i) printf("%02X ", data[i]);
    if (to_print == 0) printf("(no data)");
    printf("\n");
}


/* Backwards-compatible simple wrapper */
void decode_ethernet_and_ip_layer(const uint8_t *data, uint32_t len) {
    decode_ethernet_and_ip_layer_with_dlt(data, len, -1);
}
/* cshark_p2.c additions */

//-------#LLM Generated code ends ------------
