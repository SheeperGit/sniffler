#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "types/ARP.h"
#include "types/HTTP.h"
#include "types/ICMP.h"
#include "types/TCP.h"
#include "types/UDP.h"

#define HTTP_PORT 80
#define COL_SIZE 16

extern FILE *logfile;
struct sockaddr_in src, dst;
int tcp = 0, udp = 0, arp = 0, icmp = 0, igmp = 0, http = 0, other = 0, total = 0;  /* Counters */

void logEthHdr(unsigned char *buf, int size) {
	struct ethhdr *eth = (struct ethhdr *)buf;
	
	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
  fprintf(logfile, "\t- Src Addr : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	fprintf(logfile, "\t- Dst Addr : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	fprintf(logfile, "\t- Protocol : %u \n", (unsigned short)eth->h_proto);
}

void logIPHdr(unsigned char *buf, int size) {
	struct iphdr *iph = (struct iphdr *)(buf  + sizeof(struct ethhdr));
	
	memset(&src, 0, sizeof(src));
	src.sin_addr.s_addr = iph->saddr;
	
	memset(&dst, 0, sizeof(dst));
	dst.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, "\t- IP Version      : %d\n", (unsigned int)iph->version);
	fprintf(logfile, "\t- IP Hdr Len      : %d bytes\n", 4 * ((unsigned int)(iph->ihl)));
	fprintf(logfile, "\t- Type of Service : %d\n", (unsigned int)iph->tos);
	fprintf(logfile, "\t- IP Total Len    : %d bytes\n", ntohs(iph->tot_len));
	fprintf(logfile, "\t- ID              : %d\n", ntohs(iph->id));
	fprintf(logfile, "\t- TTL             : %d\n", (unsigned int)iph->ttl);
	fprintf(logfile, "\t- Protocol        : %d\n", (unsigned int)iph->protocol);
	fprintf(logfile, "\t- Checksum        : %d\n", ntohs(iph->check));
	fprintf(logfile, "\t- Src IP          : %s\n", inet_ntoa(src.sin_addr));
	fprintf(logfile, "\t- Dst IP          : %s\n", inet_ntoa(dst.sin_addr));
}

void dumpPkt(unsigned char *buf, int size) {
  struct ethhdr *eth = (struct ethhdr *)buf;
  unsigned short ethertype = ntohs(eth->h_proto);
  ++total;

  if (ethertype == ETH_P_ARP) { /* ARP */
    ++arp;
    log_ARP_pkt(buf, size);
  } else if (ethertype == ETH_P_IP) {
    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr)); /* Exclude Ethernet header */

    switch (iph->protocol) {
      case IPPROTO_ICMP:   /* ICMP */
        ++icmp;
        log_ICMP_pkt(buf, size);
        break;

      case IPPROTO_IGMP:   /* IGMP */
        ++igmp;
        break;

      case IPPROTO_TCP:   /* TCP */
        struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
        unsigned short iphdrlen = 4 * iph->ihl;
        struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct ethhdr) + iphdrlen);
        if (ntohs(tcph->source) == HTTP_PORT || ntohs(tcph->dest) == HTTP_PORT) { /* HTTP */
          ++http;
          log_HTTP_pkt(buf, size);
        } else {  /* (Plain) TCP */
          ++tcp;
          log_TCP_pkt(buf, size);
        }
        break;

      case IPPROTO_UDP:  /* UDP */
        ++udp;
        log_UDP_pkt(buf, size);
        break;

      default:  /* Other Unsupported Protocol Types */
        ++other;
        break;
      }
  } else {
    ++other;
  }

  /* Carriage return `\r` moves cursor back to start of current line. Allows for text overwrites. */
  printf("TCP: %d, UDP: %d, ARP: %d, ICMP: %d, IGMP: %d, HTTP: %d, Other: %d, Total: %d\r", tcp, udp, arp, icmp, igmp, http, other, total);
}

/*
* This is a hard function to understand. So, let me explain. :)
* COL_SIZE is the number of columns to print the hex codes.
* isprint() ensures that the char is printable, `.` is printed o/w. (keeps logs from looking bad)
* Run sniffler and take a look at your logfile for a concrete example!
*/
void logPktData(unsigned char *data, int size) {
	for (int i = 0; i < size; i++) {
		if (i != 0 && i % COL_SIZE == 0) {
			fprintf(logfile, "         ");
			for (int j = i - COL_SIZE; j < i; j++) {
				isprint(data[j]) ? fprintf(logfile, "%c", (unsigned char)data[j]) : fprintf(logfile, ".");
			}
			fprintf(logfile, "\n");
		} 
		
		if (i % COL_SIZE == 0) {
      fprintf(logfile, "   ");
    }

		fprintf(logfile, " %02X", (unsigned int)data[i]);
				
		if (i == size - 1) {
			for (int j = 0; j < (COL_SIZE - 1) - i % COL_SIZE; j++) {
			  fprintf(logfile, "   ");
			}
			
			fprintf(logfile, "         ");
			
			for (int j = i - i % COL_SIZE; j <= i; j++) {
        isprint(data[j]) ? fprintf(logfile, "%c", (unsigned char)data[j]) : fprintf(logfile, ".");
			}
			
			fprintf(logfile, "\n");
		}
	}
}