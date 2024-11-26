#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

void analyse(struct pcap_pkthdr *header,
              const uint8_t *packet,
              int verbose);

#endif
