#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "../log_utils.h"

extern FILE *logfile; // Defined in sniffler.c

void log_HTTP_payload(char *payload, int payload_size) {
  if (payload_size > 0) {
    fprintf(logfile, "HTTP Payload\n\t");

    for (int i = 0; i < payload_size; i++) {
      (isprint(payload[i]) || isspace(payload[i])) ? fprintf(logfile, "%c", (unsigned char)payload[i]) : fprintf(logfile, ".");
      if (payload[i] == '\n') {
        fprintf(logfile, "\t");
      }
    }
    fprintf(logfile, "\n");
  } else {
    fprintf(logfile, "Empty HTTP Payload\n");
  }
}

void log_HTTP_pkt(unsigned char *buf, int size) {
  struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
  unsigned short iphdrlen = 4 * iph->ihl;
  struct tcphdr *tcph = (struct tcphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
  unsigned int tcphdrlen = 4 * tcph->doff;
  int hdr_size = sizeof(struct ethhdr) + iphdrlen + tcphdrlen;

  char *payload = (char *)(buf + hdr_size);
  int payload_size = size - hdr_size;

  fprintf(logfile, "\n\n***********************HTTP Packet*************************\n");

  logEthHdr(buf, size);
  logIPHdr(buf, size);
  fprintf(logfile, "\n");

  fprintf(logfile, "TCP Header\n");
  fprintf(logfile, "\t- Src Port : %u\n", ntohs(tcph->source));
  fprintf(logfile, "\t- Dst Port : %u\n", ntohs(tcph->dest));
  fprintf(logfile, "\n");

  log_HTTP_payload(payload, payload_size);

  fprintf(logfile, "\n###########################################################");
}
