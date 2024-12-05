#include <stdio.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#include "../log_utils.h"

extern FILE *logfile;

void log_ARP_pkt(unsigned char *buf, int size) {
  struct ether_arp *arp = (struct ether_arp *)(buf + + sizeof(struct ethhdr));
  int hdr_size = sizeof(struct ethhdr) + sizeof(struct ether_arp);

  fprintf(logfile, "\n\n***********************ARP Packet*************************\n\n");

  fprintf(logfile, "\nARP Header\n");
  fprintf(logfile, "\t- Hardware Type : %u\n", ntohs(arp->ea_hdr.ar_hrd));
  fprintf(logfile, "\t- Protocol Type : 0x%04X\n", ntohs(arp->ea_hdr.ar_pro));
  fprintf(logfile, "\t- Hardware Size : %u\n", arp->ea_hdr.ar_hln);
  fprintf(logfile, "\t- Protocol Size : %u\n", arp->ea_hdr.ar_pln);
  fprintf(logfile, "\t- Opcode        : %u", ntohs(arp->ea_hdr.ar_op));

  switch (ntohs(arp->ea_hdr.ar_op)) {
    case ARPOP_REQUEST:
      fprintf(logfile, "\t(ARP Request)\n");
      break;
    case ARPOP_REPLY:
      fprintf(logfile, "\t(ARP Reply)\n");
      break;
    default:
      fprintf(logfile, "\t(Unknown Opcode)\n");
      break;
  }

  fprintf(logfile, "\t- Src MAC    : %02X:%02X:%02X:%02X:%02X:%02X\n", arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
  fprintf(logfile, "\t- Src IP     : %s\n", inet_ntoa(*(struct in_addr *)arp->arp_spa));
  fprintf(logfile, "\t- Dst MAC    : %02X:%02X:%02X:%02X:%02X:%02X\n", arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2], arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
  fprintf(logfile, "\t- Dst IP     : %s\n", inet_ntoa(*(struct in_addr *)arp->arp_tpa));
  fprintf(logfile, "\n");

  fprintf(logfile, "Ethernet Header\n");
  logPktData(buf, sizeof(struct ethhdr));

  fprintf(logfile, "ARP Header\n");
  logPktData(buf + sizeof(struct ethhdr), sizeof(struct ether_arp));

  fprintf(logfile, "Data Payload\n");
  logPktData(buf + hdr_size, size - hdr_size);

  fprintf(logfile, "\n###########################################################");
}
