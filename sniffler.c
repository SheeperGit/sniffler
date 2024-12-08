#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>
#include <arpa/inet.h>

#include "log_utils.h"

#define BUF_SIZE 65536  /* (65536 bytes) / (1024 bytes) = 64KB */

FILE *logfile = NULL;
int log_tcp = 1, log_udp = 1, log_arp = 1, log_icmp = 1, log_igmp = 1, log_dns = 1, log_http = 1, log_other = 1;  /* For --only */

void print_usage(const char *prog_name) {
	printf("Usage: sudo %s [OPTIONS]\n", prog_name);
	printf("\nOptions:\n");
	printf("  -q, --no-log                 Disable logging of packet details (useful for performance)\n");
	printf("  --only=<protocols>           Specify which protocols to log (comma-separated). Valid protocols: \n");
	printf("                               TCP, UDP, ARP, ICMP, IGMP, DNS, HTTP, OTHER\n");
	printf("  -o, --out=<filename>         Specify a custom filename for the log output (default is 'log.txt')\n");
	printf("  -i, --interface=<interface>  Bind to a specific network interface (e.g., eth0, enp4s0, etc.)\n");
	printf("                             	 Default is no interface binding (uses first available)\n");
	printf("\nExamples:\n");
	printf("  sudo %s --only=TCP,UDP --out=logfile.txt -i eth0\n", prog_name);
	printf("  sudo %s -q\n", prog_name);
	printf("  sudo %s --interface=eth0\n", prog_name);
	printf("  sudo %s --only=DNS --out=my_lovely_logname.txt\n", prog_name);
}

void parse_only(char *protocols) {
	log_tcp = 0, log_udp = 0, log_arp = 0, log_icmp = 0, log_igmp = 0, log_dns = 0, log_http = 0, log_other = 0;	/* Reset all */
	char *token = strtok(protocols, ",");	/* Seperate by tokens (comma-seperated values) */
	
	while (token != NULL) {
		if (strcasecmp(token, "TCP") == 0) {
			log_tcp = 1;
		} else if (strcasecmp(token, "HTTP") == 0) {
			log_http = 1;
		} else if (strcasecmp(token, "UDP") == 0) {
			log_udp = 1;
		} else if (strcasecmp(token, "DNS") == 0) {
			log_dns = 1;
		} else if (strcasecmp(token, "ARP") == 0) {
			log_arp = 1;
		} else if (strcasecmp(token, "ICMP") == 0) {
			log_icmp = 1;
		} else if (strcasecmp(token, "IGMP") == 0) {
			log_igmp = 1;
		} else if (strcasecmp(token, "OTHER") == 0) {
			log_other = 1;
		} else {
			fprintf(stderr, "Unknown protocol: %s\n", token);
		}
		token = strtok(NULL, ",");	/* Get next token */
	}
}

int main(int argc, char *argv[]) {
	int no_log = 0;
	char *log_filename = "log.txt";
	int sock_raw = 0;

	/* CLA parse */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			print_usage(argv[0]);
			return 0;
		} else if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--no-log")) {
			no_log = 1;
			break;
		} else if (strncmp(argv[i], "--only=", 7) == 0) {
			parse_only(argv[i] + 7);
		} else if (strncmp(argv[i], "-o", 2) == 0 || strncmp(argv[i], "--out", 5) == 0) {
			if (strncmp(argv[i], "--out=", 6) == 0) {
				log_filename = argv[i] + 6;
			} else if (i + 1 < argc) {
				log_filename = argv[i + 1];
				i++;	/* Skip filename arg */
			} else {
				fprintf(stderr, "Missing filename after %s\n", argv[i]);
				return 1;
			}
		} else if (strncmp(argv[i], "-i", 2) == 0 || strncmp(argv[i], "--interface=", 12) == 0) {
			char *if_name = NULL;
			if (strncmp(argv[i], "-i", 2) == 0) {
				if_name = argv[i + 1];
				i++; /* Skip netw interface name */
			} else {
				if_name = argv[i] + 12;
			}

			sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
			if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name) + 1) < 0) {
				perror("setsockopt failed");
				close(sock_raw);
				return 1;
			}
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			print_usage(argv[0]);
			return 1;
    }
	}

	if (!no_log) {
		logfile = fopen(log_filename, "w");
		if (!logfile) {
			fprintf(stderr, "Couldn't create %s file!\n", log_filename);
			return 1;
		}
	}
	
	if (!sock_raw) sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw < 0) {
		perror("Raw Socket Error: ");
		return 1;
	}

  unsigned char *buf = (unsigned char *)malloc(BUF_SIZE);
  if (!buf) {
		perror("Failed to allocate buffer!\n");
    return 1;
	}

  struct sockaddr saddr;
  printf("The Sniffler is sniffing packets...\n");
	while (1) {
		int saddr_size = sizeof(saddr);
		int data_size = recvfrom(sock_raw, buf, BUF_SIZE, 0, &saddr, (socklen_t *)&saddr_size);
		if (data_size < 0) {
			perror("recvfrom Error: ");
      free(buf);
			return 1;
		}
		dumpPkt(buf, data_size);
	}

	close(sock_raw);
  free(buf);
	if (logfile) fclose(logfile);
	printf("Exiting...");
	return 0;
}
