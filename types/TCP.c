#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "../log_utils.h"

extern FILE *logfile; // Defined in sniffler.c

void log_TCP_pkt(unsigned char *buf, int size) {
	struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	unsigned short iphdrlen = 4 * iph->ihl;
	struct tcphdr *tcph = (struct tcphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	int hdr_size = sizeof(struct ethhdr) + iphdrlen + (4 * tcph->doff);
	
	fprintf(logfile, "\n\n***********************TCP Packet*************************\n");	
		
	logIPHdr(buf, size);
		
	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, "\t- Src Port : %u\n", ntohs(tcph->source));
	fprintf(logfile, "\t- Dst Port : %u\n", ntohs(tcph->dest));
	fprintf(logfile, "\t- Seq Num  : %u\n", ntohl(tcph->seq));
	fprintf(logfile, "\t- ACK Num  : %u\n", ntohl(tcph->ack_seq));
	fprintf(logfile, "\t- Hdr Len  : %d bytes\n", 4 * (unsigned int)tcph->doff);
	fprintf(logfile, "\t- URG Flag : %d\n", (unsigned int)tcph->urg);
	fprintf(logfile, "\t- ACK Flag : %d\n", (unsigned int)tcph->ack);
	fprintf(logfile, "\t- PSH Flag : %d\n", (unsigned int)tcph->psh);
	fprintf(logfile, "\t- RST Flag : %d\n", (unsigned int)tcph->rst);
	fprintf(logfile, "\t- SYN Flag : %d\n", (unsigned int)tcph->syn);
	fprintf(logfile, "\t- FIN Flag : %d\n", (unsigned int)tcph->fin);
	fprintf(logfile, "\t- Window   : %d\n", ntohs(tcph->window));
	fprintf(logfile, "\t- Checksum : %d\n", ntohs(tcph->check));
	fprintf(logfile, "\t- Urg Ptr  : %d\n", tcph->urg_ptr);
	fprintf(logfile, "\n");
	fprintf(logfile, "                        DATA Dump                         ");
	fprintf(logfile, "\n");
		
	fprintf(logfile, "IP Header\n");
	logPktData(buf, iphdrlen);
		
	fprintf(logfile, "TCP Header\n");
	logPktData(buf + iphdrlen, 4 * tcph->doff);
		
	fprintf(logfile, "Data Payload\n");	
	logPktData(buf + hdr_size, size - hdr_size);
						
	fprintf(logfile, "\n###########################################################");
}