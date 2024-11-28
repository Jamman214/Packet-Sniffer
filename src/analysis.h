#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include "dispatch.h"

void analyse(struct ThreadData* threadData, 
             const struct pcap_pkthdr* header,
             const uint8_t* packet);

#endif
