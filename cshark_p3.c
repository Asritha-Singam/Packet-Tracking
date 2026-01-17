//-------#LLM Generated code begins ------------

#define _POSIX_C_SOURCE 200809L
#include "cshark_p3.h"
#include "cshark_p4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/select.h>
#include <pcap.h>

static volatile sig_atomic_t p3_sigint_received = 0;
static volatile sig_atomic_t p3_exit_requested = 0;
static volatile sig_atomic_t p3_stop_monitor = 0;
static pcap_t *p3_handle = NULL;

void p3_handle_sigint(int signo) {
    (void)signo;
    p3_sigint_received = 1;
    if (p3_handle) pcap_breakloop(p3_handle);
}

static void *p3_stdin_monitor(void *arg) {
    (void)arg;
    while (!p3_stop_monitor) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        struct timeval tv = {0, 500000};
        int r = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
        if (r > 0 && FD_ISSET(STDIN_FILENO, &rfds)) {
            char buf[128];
            if (fgets(buf, sizeof(buf), stdin) == NULL) {
                p3_exit_requested = 1;
                if (p3_handle) pcap_breakloop(p3_handle);
                break;
            }
            /* consume input and ignore */
        }
    }
    return NULL;
}

static const char *choice_to_bpf(int choice) {
    switch (choice) {
        case 1: return "tcp port 80";
        case 2: return "tcp port 443";
        case 3: return "port 53";
        case 4: return "arp";
        case 5: return "tcp";
        case 6: return "udp";
        default: return NULL;
    }
}

int start_sniffing_with_filter(const char *devname, pcap_handler handler, u_char *user) {
    if (!devname || !handler) return -1;
    printf("[C-Shark] Filtered sniffing selected.\n");
    printf("Choose a filter:\n");
    printf(" 1. HTTP (tcp port 80)\n");
    printf(" 2. HTTPS (tcp port 443)\n");
    printf(" 3. DNS (port 53)\n");
    printf(" 4. ARP (arp)\n");
    printf(" 5. TCP (all)\n");
    printf(" 6. UDP (all)\n");
    printf("Select an option (1-6): ");

    char line[128];
    if (fgets(line, sizeof(line), stdin) == NULL) { printf("\n[C-Shark] Ctrl+D detected. Exiting.\n"); return 1; }
    int sel = 0;
    if (sscanf(line, "%d", &sel) != 1 || sel < 1 || sel > 6) { printf("Invalid selection. Returning to menu.\n"); return 0; }
    const char *bpf = choice_to_bpf(sel);
    if (!bpf) return 0;

    char errbuf[PCAP_ERRBUF_SIZE];

    /* Use pcap_create/pcap_set_* + pcap_activate: more control and better for 'any' */
    pcap_t *handle = pcap_create(devname, errbuf);
    if (!handle) {
        fprintf(stderr, "[C-Shark] pcap_create failed for %s: %s\n", devname, errbuf);
        return -1;
    }

    /* Snaplen, promisc, timeout - tune as you need */
    if (pcap_set_snaplen(handle, 65535) != 0) {
        fprintf(stderr, "[C-Shark] pcap_set_snaplen failed: %s\n", pcap_geterr(handle));
        pcap_close(handle); return -1;
    }
    /* promiscuous mode: on most devices ok; for 'any' it's ignored */
    if (pcap_set_promisc(handle, 1) != 0) {
        fprintf(stderr, "[C-Shark] pcap_set_promisc failed: %s\n", pcap_geterr(handle));
        /* continue — some platforms ignore this */
    }
    if (pcap_set_timeout(handle, 1000) != 0) {
        fprintf(stderr, "[C-Shark] pcap_set_timeout failed: %s\n", pcap_geterr(handle));
    }
    /* Activate */
    int ac = pcap_activate(handle);
    if (ac != 0) {
        /* pcap_activate returns PCAP_ERROR/PCAP_WARNING codes. Get text and bail. */
        fprintf(stderr, "[C-Shark] pcap_activate returned %d: %s\n", ac, pcap_geterr(handle));
        pcap_close(handle); return -1;
    }

    /* Compile & set BPF filter. Try PCAP_NETMASK_UNKNOWN first and if that fails,
       try with a fallback netmask of 0xffffffff (useful for weird devices). */
    struct bpf_program prog;
    //int compile_ok = 0;
    if (pcap_compile(handle, &prog, bpf, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        //compile_ok = 1;
    } else {
        /* fallback try */
        unsigned int fallback_netmask = 0xFFFFFFFF;
        if (pcap_compile(handle, &prog, bpf, 1, fallback_netmask) == 0) {
            //compile_ok = 1;
        } else {
            fprintf(stderr, "[C-Shark] pcap_compile failed (tried unknown and fallback): %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
    }

    if (pcap_setfilter(handle, &prog) == -1) {
        fprintf(stderr, "[C-Shark] pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&prog); pcap_close(handle); return -1;
    }
    pcap_freecode(&prog);

    /* Install SIGINT handler and prepare stdin monitor as before */
    struct sigaction sa;
    sa.sa_handler = p3_handle_sigint;
    sigemptyset(&sa.sa_mask); sa.sa_flags=0; sigaction(SIGINT, &sa, NULL);

    p3_sigint_received = 0; p3_exit_requested = 0; p3_stop_monitor = 0; p3_handle = handle;
    pthread_t mon_thread;
    if (pthread_create(&mon_thread, NULL, p3_stdin_monitor, NULL) != 0) perror("pthread_create");

    /* Print datalink info (useful to choose parsing) */
    int dlt = pcap_datalink(handle);
    const char *dlt_name = pcap_datalink_val_to_name(dlt);
    const char *dlt_desc = pcap_datalink_val_to_description(dlt);
    if (!dlt_name) dlt_name = "UNKNOWN";
    if (!dlt_desc) dlt_desc = "";
    printf("[C-Shark] Starting filtered capture on '%s' with filter '%s'... (Ctrl+C stop, Ctrl+D exit)\n", devname, bpf);
    printf("[C-Shark] Datalink: %s (%d) - %s\n", dlt_name, dlt, dlt_desc);

    cshark_current_dlt = dlt;
    p4_session_set_dlt(dlt);


    /* Record the datalink for session storage or downstream decoders:
       If you have a p4 API to store metadata, add a setter or pass dlt when starting session.
       For now we print it and (optionally) you can add p4_session_set_dlt(dlt) if implemented. */
    if (p4_session_start() != 0) {
        fprintf(stderr, "[C-Shark] Warning: session storage start failed\n");
    } else {
        /* optional: call a function to save dlt if you extend p4 to keep metadata */
        /* p4_session_set_dlt(dlt); */
    }

    /* Run loop (infinite until break). packet handler should use pcap_datalink(handle)
       or a saved global_dlt to parse link-layer correctly. */
    int ret = pcap_loop(handle, -1, handler, user);
    if (ret == -1) fprintf(stderr, "[C-Shark] pcap_loop error: %s\n", pcap_geterr(handle));
    else if (ret == -2) fprintf(stderr, "[C-Shark] pcap_loop terminated by pcap_breakloop() / signal\n");

    /* cleanup */
    p3_stop_monitor = 1;
    pthread_join(mon_thread, NULL);
    pcap_close(handle);
    p3_handle = NULL;

    if (p3_exit_requested) { printf("[C-Shark] Ctrl+D detected: exiting application.\n"); return 1; }
    if (p3_sigint_received) { p3_sigint_received = 0; printf("[C-Shark] Ctrl+C detected: stopping capture, returning to menu.\n"); return 0; }

    printf("[C-Shark] Filtered capture ended. Returning to main menu.\n");
    return 0;
}
//-------#LLM Generated code ends ------------

