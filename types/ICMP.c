#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "../log_utils.h"

extern FILE *logfile;

void log_ICMP_pkt(unsigned char *buf, int size) {
	struct iphdr *iph = (struct iphdr *)(buf  + sizeof(struct ethhdr));
	unsigned short iphdrlen = 4 * iph->ihl;
	struct icmphdr *icmph = (struct icmphdr *)(buf + iphdrlen  + sizeof(struct ethhdr));
	int hdr_size = sizeof(struct ethhdr) + iphdrlen + sizeof(icmph);
	
	fprintf(logfile, "\n\n***********************ICMP Packet*************************\n");	
	
	logIPHdr(buf, size);
			
	fprintf(logfile, "\n");
		
	fprintf(logfile, "ICMP Header\n");
	fprintf(logfile, "\t- Type     : %d", (unsigned int)(icmph->type));
			
	switch ((unsigned int)icmph->type) {
    case ICMP_ECHO:
      fprintf(logfile, "\t(ICMP Echo Request)\n");
      break;
    case ICMP_ECHOREPLY:
      fprintf(logfile, "\t(ICMP Echo Reply)\n");
      break;
    case ICMP_DEST_UNREACH:
      fprintf(logfile, "\t(ICMP Destination Unreachable)\n");
      break;
    case ICMP_REDIRECT:
      fprintf(logfile, "\t(ICMP Redirect)\n");
      break;
    case ICMP_TIME_EXCEEDED:
      fprintf(logfile, "\t(TTL Expired)\n");
      break;
    default:
      fprintf(logfile, "\t(Unknown ICMP Type: %d)\n", (unsigned int)icmph->type);
      break;
  }
	
	fprintf(logfile, "\t- Code     : %d\n", (unsigned int)(icmph->code));
	fprintf(logfile, "\t- Checksum : %d\n", ntohs(icmph->checksum));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	logPktData(buf, iphdrlen);
		
	fprintf(logfile, "UDP Header\n");
	logPktData(buf + iphdrlen, sizeof(icmph));
		
	fprintf(logfile, "Data Payload\n");	
	logPktData(buf + hdr_size, size - hdr_size);
	
	fprintf(logfile, "\n###########################################################");
}