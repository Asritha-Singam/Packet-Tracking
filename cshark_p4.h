//-------#LLM Generated code begins ------------

#ifndef CSHARK_P4_H
#define CSHARK_P4_H

#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
typedef uint8_t  u_char;
typedef uint16_t u_short;
typedef uint32_t u_int;
#include <pcap.h>
#include <sys/time.h>

#ifndef MAX_PACKETS
#define MAX_PACKETS 10000
#endif

struct p4_packet_meta {
    unsigned id;
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

int p4_session_start(void);
int p4_store_packet(const struct pcap_pkthdr *hdr, const u_char *data);
void p4_free_session(void);
unsigned p4_get_count(void);
int p4_has_session(void);
void p4_list_summaries(void);
int p4_get_packet(unsigned index, const struct p4_packet_meta **out_meta, const u_char **out_data);
void inspect_stored_packet(void);
int p4_session_get_dlt(void);
void p4_session_set_dlt(int dlt);

#endif // CSHARK_P4_H
//-------#LLM Generated code ends ------------
