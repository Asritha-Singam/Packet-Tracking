//-------#LLM Generated code begins ------------

#ifndef CSHARK_P2_H
#define CSHARK_P2_H

#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
typedef uint8_t  u_char;
typedef uint16_t u_short;
typedef uint32_t u_int;
#include <pcap.h>

/* Lower-level decoders */
void decode_ipv4(const uint8_t *ip_ptr, uint32_t avail_len);
void decode_ipv6(const uint8_t *ip6_ptr, uint32_t avail_len);
void decode_arp(const uint8_t *arp_ptr, uint32_t avail_len);
void format_mac(const uint8_t *mac, char *dst, size_t dstsz);

extern int cshark_current_dlt;

#endif // CSHARK_P2_H
//-------#LLM Generated code ends ------------
