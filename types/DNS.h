#ifndef _DNS_H
#define _DNS_H

struct dnshdr {
  unsigned short id;     /* ID */
  unsigned short flags;  /* Flags */
  unsigned short qn_amt; /* Amount of questions */
  unsigned short an_amt; /* Amount of answers */
  unsigned short ns_amt; /* Amount of authority records */
  unsigned short ar_amt; /* Amount of additional records */
};

void log_DNS_qns(int qn_amt, unsigned char *dns_data);

void log_DNS_pkt(unsigned char *buf, int size);

#endif