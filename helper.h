//-------#LLM Generated code begins ------------

#ifndef HELPER_H
#define HELPER_H


#include <stdint.h>
typedef uint8_t  u_char;
typedef uint16_t u_short;
typedef uint32_t u_int;
#include <pcap.h>

/* Top-level decoder entry used by main: it will try to handle Ethernet, SLL, or direct IP.
   If dlt >= 0 pass the datalink type (pcap_datalink); if dlt < 0 decoder will attempt to auto-detect. */
void decode_ethernet_and_ip_layer_with_dlt(const uint8_t *data, uint32_t len, int dlt);

/* Convenience (legacy) name kept for compatibility */
void decode_ethernet_and_ip_layer(const uint8_t *data, uint32_t len);


#endif
//-------#LLM Generated code ends ------------
