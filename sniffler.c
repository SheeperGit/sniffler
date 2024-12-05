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

FILE *logfile;

int main(int argc, char *argv[]) {
	logfile = fopen("log.txt", "w");
	if (!logfile) {
		perror("Couldn't create log.txt file!\n");
    return 1;
	}
	
	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	// setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, "eth0", strlen("eth0") + 1); // Choose IF `eth0` to sniff from
	
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
	printf("Exiting...");
	return 0;
}
