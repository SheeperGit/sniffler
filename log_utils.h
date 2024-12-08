#ifndef _LOG_UTILS_H
#define _LOG_UTILS_H

void logEthHdr(unsigned char *buf, int size);
void logIPHdr(unsigned char *buf, int size);
void dumpPkt(unsigned char *buf, int size);
void logPktData(unsigned char *data, int size);

#endif