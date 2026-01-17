//-------#LLM Generated code begins ------------

#define _POSIX_C_SOURCE 200809L
#include "cshark_p4.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "helper.h"
/* at top of cshark_p4.c */
static int p4_session_dlt = -1;

/* add helper setter */
void p4_session_set_dlt(int dlt) { p4_session_dlt = dlt; }
int p4_session_get_dlt(void) { return p4_session_dlt; }


struct p4_entry {
    struct p4_packet_meta meta;
    u_char *data; /* malloced copy, size meta.caplen */
};

static struct p4_entry *p4_buffer = NULL;
static unsigned p4_count = 0;
static pthread_mutex_t p4_lock = PTHREAD_MUTEX_INITIALIZER;

/* Start new session: free previous session and allocate small buffer (grow dynamically) */
int p4_session_start(void) {
    pthread_mutex_lock(&p4_lock);
    if (p4_buffer) {
        /* free previous */
        for (unsigned i=0;i<p4_count;++i) free(p4_buffer[i].data);
        free(p4_buffer);
        p4_buffer = NULL;
        p4_count = 0;
    }
    /* allocate initial capacity (lazy) */
    p4_buffer = malloc(sizeof(struct p4_entry) * 256);
    if (!p4_buffer) { pthread_mutex_unlock(&p4_lock); return -1; }
    /* zero entries */
    memset(p4_buffer, 0, sizeof(struct p4_entry) * 256);
    p4_count = 0;
    pthread_mutex_unlock(&p4_lock);
    return 0;
}

/* Store a copy of captured packet: thread-safe */
int p4_store_packet(const struct pcap_pkthdr *hdr, const u_char *data) {
    if (!hdr || !data) return -1;
    pthread_mutex_lock(&p4_lock);
    if (!p4_buffer) { pthread_mutex_unlock(&p4_lock); return -1; }
    if (p4_count >= MAX_PACKETS) { pthread_mutex_unlock(&p4_lock); return 1; }

    /* expand if needed */
    static unsigned capacity = 256;
    if (p4_count >= capacity) {
        unsigned newcap = capacity * 2;
        struct p4_entry *tmp = realloc(p4_buffer, sizeof(struct p4_entry) * newcap);
        if (!tmp) { pthread_mutex_unlock(&p4_lock); return -1; }
        /* zero new area */
        memset(tmp + capacity, 0, sizeof(struct p4_entry) * (newcap - capacity));
        p4_buffer = tmp;
        capacity = newcap;
    }

    struct p4_entry *e = &p4_buffer[p4_count];
    e->meta.id = p4_count + 1;
    e->meta.ts = hdr->ts;
    e->meta.caplen = hdr->caplen;
    e->meta.len = hdr->len;
    e->data = malloc(hdr->caplen ? hdr->caplen : 1);
    if (!e->data) { pthread_mutex_unlock(&p4_lock); return -1; }
    memcpy(e->data, data, hdr->caplen);
    p4_count++;
    pthread_mutex_unlock(&p4_lock);
    return 0;
}

void p4_free_session(void) {
    pthread_mutex_lock(&p4_lock);
    if (p4_buffer) {
        for (unsigned i=0;i<p4_count;++i) free(p4_buffer[i].data);
        free(p4_buffer);
    }
    p4_buffer = NULL;
    p4_count = 0;
    pthread_mutex_unlock(&p4_lock);
}

unsigned p4_get_count(void) {
    pthread_mutex_lock(&p4_lock);
    unsigned c = p4_count;
    pthread_mutex_unlock(&p4_lock);
    return c;
}

int p4_has_session(void) {
    pthread_mutex_lock(&p4_lock);
    int has = (p4_buffer && p4_count > 0) ? 1 : 0;
    pthread_mutex_unlock(&p4_lock);
    return has;
}

void p4_list_summaries(void) {
    pthread_mutex_lock(&p4_lock);
    if (!p4_buffer || p4_count == 0) {
        printf("No stored packets (last session empty)\n");
        pthread_mutex_unlock(&p4_lock);
        return;
    }
    printf("Stored packets (last session):\n");
    for (unsigned i=0;i<p4_count;++i) {
        struct p4_packet_meta *m = &p4_buffer[i].meta;
        printf("%4u | Timestamp: %ld.%06ld | Length: %u\n",
               m->id, (long)m->ts.tv_sec, (long)m->ts.tv_usec, (unsigned)m->len);
    }
    pthread_mutex_unlock(&p4_lock);
}

int p4_get_packet(unsigned index, const struct p4_packet_meta **out_meta, const u_char **out_data) {
    if (!out_meta || !out_data) return -1;
    pthread_mutex_lock(&p4_lock);
    if (!p4_buffer) { pthread_mutex_unlock(&p4_lock); return -1; }
    if (index < 1 || index > p4_count) { pthread_mutex_unlock(&p4_lock); return -1; }
    unsigned idx = index - 1;
    *out_meta = &p4_buffer[idx].meta;
    *out_data = p4_buffer[idx].data;
    pthread_mutex_unlock(&p4_lock);
    return 0;
}

/* Interactive inspect stored packet (used from main menu) */
void inspect_stored_packet(void) {
    pthread_mutex_lock(&p4_lock);
    if (!p4_buffer || p4_count == 0) {
        pthread_mutex_unlock(&p4_lock);
        printf("[C-Shark] No stored session to inspect. Run a capture first.\n");
        return;
    }
    unsigned count = p4_count;
    pthread_mutex_unlock(&p4_lock);

    p4_list_summaries();
    printf("\nEnter Packet ID to inspect (1-%u): ", count);
    char line[128];
    if (fgets(line, sizeof(line), stdin) == NULL) { printf("\n[C-Shark] Ctrl+D detected.\n"); return; }
    unsigned sel = 0;
    if (sscanf(line, "%u", &sel) != 1 || sel < 1 || sel > count) { printf("Invalid selection.\n"); return; }

    const struct p4_packet_meta *meta = NULL;
    const u_char *data = NULL;
    if (p4_get_packet(sel, &meta, &data) != 0) { printf("Failed to retrieve packet.\n"); return; }

    printf("-----------------------------------------\n");
    printf("Inspecting Packet #%u | Timestamp: %ld.%06ld | Length: %u\n",
           meta->id, (long)meta->ts.tv_sec, (long)meta->ts.tv_usec, (unsigned)meta->len);
    /* Print full hex dump of entire frame (caplen bytes) */
    printf("Full hex dump (%u bytes):\n", (unsigned)meta->caplen);
    for (unsigned i=0;i<meta->caplen;i+=16) {
        unsigned line_len = (meta->caplen - i >= 16) ? 16 : (meta->caplen - i);
        printf("%04X  ", i);
        for (unsigned j=0;j<line_len;++j) printf("%02X ", data[i+j]);
        if (line_len < 16) for (unsigned p=0;p<16-line_len;++p) printf("   ");
        printf(" ");
        for (unsigned j=0;j<line_len;++j) {
            unsigned char c = data[i+j];
            putchar((c>=32 && c<=126) ? c : '.');
        }
        printf("\n");
    }

    /* Also decode layers using p2 module (reuse existing decoder) */
    decode_ethernet_and_ip_layer_with_dlt(data, meta->caplen, p4_session_get_dlt());
}
//-------#LLM Generated code ends------------
