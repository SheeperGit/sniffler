#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../log_utils.h"

extern FILE *logfile;

void log_UDP_pkt(unsigned char *buf, int size) {
	struct iphdr *iph = (struct iphdr *)(buf +  sizeof(struct ethhdr));
	unsigned short iphdrlen = 4 * iph->ihl;
	struct udphdr *udph = (struct udphdr *)(buf + iphdrlen  + sizeof(struct ethhdr));
	int hdr_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(udph);
	
	fprintf(logfile, "\n\n***********************UDP Packet*************************\n");
	
	logIPHdr(buf, size);
	
	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, "\t- Src Port     : %d\n", ntohs(udph->source));
	fprintf(logfile, "\t- Dst Port     : %d\n", ntohs(udph->dest));
	fprintf(logfile, "\t- UDP Hdr Len  : %d\n", ntohs(udph->len));
	fprintf(logfile, "\t- UDP Checksum : %d\n", ntohs(udph->check));
	
	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	logPktData(buf, iphdrlen);
		
	fprintf(logfile, "UDP Header\n");
	logPktData(buf + iphdrlen, sizeof(udph));
		
	fprintf(logfile, "Data Payload\n");
	logPktData(buf + hdr_size, size - hdr_size);
	
	fprintf(logfile, "\n###########################################################");
}