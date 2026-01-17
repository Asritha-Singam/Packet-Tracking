//-------#LLM Generated code begins ------------
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <sys/types.h>
typedef uint8_t  u_char;
typedef uint16_t u_short;
typedef uint32_t u_int;

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/select.h>

#include "cshark_p2.h"
#include "cshark_p3.h"
#include "cshark_p4.h"
#include "helper.h"

volatile sig_atomic_t sigint_received = 0;
volatile sig_atomic_t exit_requested = 0;
volatile sig_atomic_t stop_monitor = 0;
pcap_t *global_handle = NULL;

void handle_sigint(int signo) {
    (void)signo;
    sigint_received = 1;
    if (global_handle) pcap_breakloop(global_handle);
}

void print_banner(void) {
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
}

void hexdump16(const u_char *data, bpf_u_int32 len) {
    bpf_u_int32 to_print = (len < 16) ? len : 16;
    for (bpf_u_int32 i = 0; i < to_print; ++i) {
        printf("%02X ", data[i]);
    }
    if (to_print == 0) printf("(no data)");
    printf("\n");
}

/* packet_handler used by pcap_loop: prints header summary, saves to P4, then calls L2/L3 decoder */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    unsigned long *pktid = (unsigned long*) user;
    (*pktid)++;

    printf("-----------------------------------------\n");
    printf("Packet #%lu | Timestamp: %ld.%06ld | Length : %u\n",
           *pktid, (long)h->ts.tv_sec, (long)h->ts.tv_usec, (unsigned)h->len);

    /* store for phase 4 (makes a copy) */
    int r = p4_store_packet(h, bytes);
    (void)r;

    /* call decoder — decode_ethernet_and_ip_layer will handle Ethernet or SLL or direct IP */
    decode_ethernet_and_ip_layer_with_dlt(bytes, h->caplen, cshark_current_dlt); // dlt = -1 unknown here (ph1 used pcap_datalink outside)
    fflush(stdout);
}

/* list devices */
struct dev_entry { char *name; char *desc; };

int list_devices(struct dev_entry **out_devs, int *out_n) {
    pcap_if_t *alldevs = NULL, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    int cnt = 0;
    for (d = alldevs; d; d = d->next) cnt++;
    if (cnt == 0) { pcap_freealldevs(alldevs); *out_devs = NULL; *out_n = 0; return 0; }
    struct dev_entry *arr = calloc(cnt, sizeof(struct dev_entry));
    if (!arr) { pcap_freealldevs(alldevs); perror("calloc"); return -1; }
    int i=0;
    for (d = alldevs; d; d = d->next) {
        arr[i].name = strdup(d->name);
        if (d->description) arr[i].desc = strdup(d->description);
        else arr[i].desc = strdup("(No description)");
        i++;
    }
    pcap_freealldevs(alldevs);
    *out_devs = arr; *out_n = cnt;
    return 0;
}
void free_devices(struct dev_entry *devs, int n) {
    if (!devs) return;
    for (int i=0;i<n;++i){ free(devs[i].name); free(devs[i].desc); }
    free(devs);
}

/* stdin monitor thread to detect Ctrl+D (EOF) while capture */
void *stdin_monitor_thread(void *arg) {
    (void)arg;
    while (!stop_monitor) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        struct timeval tv = {0, 500000};
        int r = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
        if (r > 0 && FD_ISSET(STDIN_FILENO, &rfds)) {
            char buf[128];
            if (fgets(buf, sizeof(buf), stdin) == NULL) {
                exit_requested = 1;
                if (global_handle) pcap_breakloop(global_handle);
                break;
            } else {
                /* consumed a line, ignore */
                continue;
            }
        }
    }
    return NULL;
}

/* Phase1: start sniffing all packets on interface devname */
int start_sniffing_all(const char *devname) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(devname, 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed for %s: %s\n", devname, errbuf);
        return -1;
    }
    global_handle = handle;

    

    int dlt = pcap_datalink(handle);

    cshark_current_dlt = dlt;

    p4_session_set_dlt(dlt);
    const char *dltname = pcap_datalink_val_to_name(dlt);
    printf("Datalink type: %s (%d)\n", dltname ? dltname : "unknown", dlt);

    /* signal to break loop on Ctrl+C */
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    unsigned long pktid = 0;
    stop_monitor = 0;
    pthread_t mon_thread;
    if (pthread_create(&mon_thread, NULL, stdin_monitor_thread, NULL) != 0) {
        perror("pthread_create (stdin monitor)");
    }else{
        printf("pthread monitor created\n");
    }

    if (p4_session_start() != 0) {
        fprintf(stderr, "[C-Shark] Warning: session storage failed to start\n");
    }

    printf("[C-Shark] Starting capture on interface '%s'... (Press Ctrl+C to stop capture, Ctrl+D to exit)\n", devname);



    /* We'll call pcap_loop with a wrapper that calls decode_ethernet_and_ip_layer_with_dlt.
       Create an adapter callback inline via a small function closure is not possible in C,
       so instead we'll use a global pointer hack: set a static variable used by the decoder.
       But to stay minimal, we simply call pcap_loop with our packet_handler which calls decoder with dlt=-1.
       To keep DLT known, we can set global_handle_dlt in p2 module — simpler: call pcap_loop and in packet handler
       call pcap_datalink(handle) each time (cheap) and pass to decoder. */


    int ret = pcap_loop(handle, -1, packet_handler, (u_char*)&pktid);
    if (ret == -1) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
    } else if (ret == -2) {
        /* loop terminated by pcap_breakloop */
    }

    stop_monitor = 1;
    pthread_join(mon_thread, NULL);

    pcap_close(handle);
    global_handle = NULL;

    if (exit_requested) {
        printf("[C-Shark] Ctrl+D detected: exiting application.\n");
        return 1;
    }
    if (sigint_received) {
        sigint_received = 0;
        printf("[C-Shark] Capture stopped (Ctrl+C). Returning to main menu.\n");
        return 0;
    }
    printf("[C-Shark] Capture ended. Returning to main menu.\n");
    return 0;
}

int main(void) {
    print_banner();

    struct dev_entry *devs = NULL;
    int ndevs = 0;
    if (list_devices(&devs, &ndevs) != 0) return 1;
    if (ndevs == 0) { printf("[C-Shark] No interfaces found. Exiting.\n"); return 0; }

    printf("[C-Shark] Searching for available interfaces... Found!\n\n");
    for (int i = 0; i < ndevs; ++i) {
        printf("%2d. %s\t%s\n", i + 1, devs[i].name, devs[i].desc);
    }

    char line[128];
    int sel = -1;
    while (1) {
        printf("\nSelect an interface to sniff (1-%d): ", ndevs);
        if (fgets(line, sizeof(line), stdin) == NULL) {
            printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
            free_devices(devs, ndevs);
            return 0;
        }
        if (sscanf(line, "%d", &sel) != 1) { printf("Invalid selection.\n"); continue; }
        if (sel < 1 || sel > ndevs) { printf("Out of range.\n"); continue; }
        break;
    }
    const char *selected_dev = devs[sel - 1].name;

    for (;;) {
        printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", selected_dev);
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters)\n");
        printf("3. Inspect Last Session\n");
        printf("4. Exit C-Shark\n\n");
        printf("Choose an option (1-4): ");
        if (fgets(line, sizeof(line), stdin) == NULL) {
            printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
            break;
        }
        int choice = 0;
        if (sscanf(line, "%d", &choice) != 1) { printf("Invalid choice.\n"); continue; }
        if (choice == 1) {
            int r = start_sniffing_all(selected_dev);
            if (r == 1) break;
        } else if (choice == 2) {
            unsigned long pktid = 0;
            int r = start_sniffing_with_filter(selected_dev, packet_handler, (u_char*)&pktid);
            if (r == 1) break; /* exit */
        } else if (choice == 3) {
            inspect_stored_packet();
        } else if (choice == 4) {
            printf("[C-Shark] Exiting. Goodbye.\n");
            break;
        } else {
            printf("Invalid choice.\n");
        }
    }

    free_devices(devs, ndevs);
    return 0;
}
//-------#LLM Generated code ends ------------
