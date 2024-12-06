#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../log_utils.h"

#define MAX_DNAME_LEN 256

extern FILE *logfile;

struct dnshdr {
  unsigned short id;     /* ID */
  unsigned short flags;  /* Flags */
  unsigned short qn_amt; /* Amount of questions */
  unsigned short an_amt; /* Amount of answers */
  unsigned short ns_amt; /* Amount of authority records */
  unsigned short ar_amt; /* Amount of additional records */
};

void log_DNS_qns(int qn_amt, unsigned char *dns_data) {
  unsigned char *q_ptr = dns_data + sizeof(struct dnshdr);
  for (int i = 0; i < qn_amt; i++) {
    fprintf(logfile, "\nDNS Question %d\n", i + 1);

    char dname[MAX_DNAME_LEN];
    int j = 0;
    while (*q_ptr && j < sizeof(dname) - 1) {
      int label_len = *q_ptr;
      q_ptr++;
      if (label_len > 63) break; /* Invalid length */
      while (label_len-- > 0) {
        dname[j] = *q_ptr;
        j++;
        q_ptr++;
      }
      dname[j] = '.';
      j++;
    }

    dname[j - 1] = '\0';
    q_ptr++;

    fprintf(logfile, "\t- Domain Name    : %s\n", dname);

    unsigned short qtype = ntohs(*(unsigned short *)q_ptr);
    q_ptr += 2;
    unsigned short qclass = ntohs(*(unsigned short *)q_ptr);

    fprintf(logfile, "\t- Question Type  : %d\n", qtype);
    fprintf(logfile, "\t- Question Class : %d\n", qclass);
  }
}

/* 
* Operates under the assumption that the DNS packet is done over UDP. 
* In reality, DNS uses both UDP and TCP for different types of queries.
* See https://en.wikipedia.org/wiki/Domain_Name_System for details.
*/
void log_DNS_pkt(unsigned char *buf, int size) {
  struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
  unsigned short iphdrlen = 4 * iph->ihl;
  unsigned short udp_hdrlen = sizeof(struct udphdr);

  unsigned char *dns_data = buf + sizeof(struct ethhdr) + iphdrlen + udp_hdrlen;
  int dns_size = size - (sizeof(struct ethhdr) + iphdrlen + udp_hdrlen);

  if (dns_size <= 0) {
    fprintf(logfile, "\n\n***********************DNS Packet*************************\n");
    fprintf(logfile, "Error: Invalid DNS payload size\n");
    fprintf(logfile, "\n###########################################################\n");
    return;
  }

  fprintf(logfile, "\n\n***********************DNS Packet*************************\n");
  fprintf(logfile, "IP Header\n");
  logPktData(buf, iphdrlen);

  fprintf(logfile, "UDP Header\n");
  logPktData(buf + sizeof(struct ethhdr) + iphdrlen, udp_hdrlen);

  fprintf(logfile, "DNS Payload\n");
  logPktData(dns_data, dns_size);

  struct dnshdr *dnsh = (struct dnshdr *)dns_data;

  fprintf(logfile, "\nDNS Header\n");
  fprintf(logfile, "\t- ID             : 0x%04X\n", ntohs(dnsh->id));
  fprintf(logfile, "\t- Flags          : 0x%04X\n", ntohs(dnsh->flags));
  fprintf(logfile, "\t- Questions      : %d\n", ntohs(dnsh->qn_amt));
  fprintf(logfile, "\t- Answers        : %d\n", ntohs(dnsh->an_amt));
  fprintf(logfile, "\t- Authority      : %d\n", ntohs(dnsh->ns_amt));
  fprintf(logfile, "\t- Additional     : %d\n", ntohs(dnsh->ar_amt));

  log_DNS_qns(ntohs(dnsh->qn_amt), dns_data);

  fprintf(logfile, "\n###########################################################\n");
}
