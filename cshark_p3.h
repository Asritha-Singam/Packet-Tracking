//-------#LLM Generated code begins ------------

#ifndef CSHARK_P3_H
#define CSHARK_P3_H

#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
typedef uint8_t  u_char;
typedef uint16_t u_short;
typedef uint32_t u_int;
#include <pcap.h>

extern int cshark_current_dlt;

/* start_sniffing_with_filter:
   - devname: interface name
   - handler: pcap_handler (callback)
   - user: user pointer passed to handler
   returns: 0 -> stop via Ctrl+C (return to menu)
            1 -> stop via Ctrl+D (request exit of whole program)
           -1 -> fatal error
*/
int start_sniffing_with_filter(const char *devname, pcap_handler handler, u_char *user);

#endif // CSHARK_P3_H
//-------#LLM Generated code ends ------------
