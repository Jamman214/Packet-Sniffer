#include "analysis.h"

#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h> // ntohs
#include <net/ethernet.h> // ETHERTYPE_IP, ETHERTYPE_ARP
#include <net/if_arp.h> // arphdr, ARPOP_REPLY
#include <netinet/ip.h> // ip
#include <netinet/tcp.h> // tcphdr, TH_SYN
#include <netinet/in.h> // IPPROTO_TCP

// void analyse(struct pcap_pkthdr *header, const uint8_t *packet, int verbose) {
// }

void printIP(const uint8_t* ip) {
    int i;
    for (i=0; i<4; i++) {
        printf("%d", *(ip+i));
        if (i<3) {
            printf(":");
        }
    }
}

void violation(struct SharedData* shared, const struct ip* IPHeader, char* host) {
    pthread_mutex_lock(&shared->print_lock);
        printf("========================================\n");
        printf("Blacklisted URL violation detected\n");
        printf("Source IP address: ");
        printIP((const uint8_t*)&(IPHeader->ip_src));
        printf("\nDestination IP address: ");
        printIP((const uint8_t*)&(IPHeader->ip_dst));
        printf(" (");
        printf(host);
        printf(")\n========================================\n");
    pthread_mutex_unlock(&shared->print_lock);
}

void analyseHTTP(struct ThreadData* threadData, const struct ip* IPHeader, const char* Packet, int packetLength) {
    char* httpString = (char*)malloc(packetLength + sizeof(char));
    httpString[packetLength] = '\0';
    strncpy(httpString, Packet, packetLength);

    const char* headerEnd = strstr(httpString, "\r\n\r\n");
    if (headerEnd == NULL) {
        free(httpString);
        return;
    }
    
    char* hostStart = strstr(httpString, "Host: ");
    if (hostStart == NULL || hostStart > headerEnd) {
        free(httpString);
        return;
    }

    hostStart += 6;
    const char* hostEnd = strstr(hostStart, "\r\n");
    int hostLen = hostEnd - hostStart;
    char* host = (char*)malloc(hostLen + sizeof(char));
    host[hostLen] = '\0';
    strncpy(host, hostStart, hostLen);

    if (strcmp(host, "www.google.co.uk") == 0) {
        threadData->individual->blackListCount[0] += 1;
        violation(threadData->shared, IPHeader, "google");
    } else if (strcmp(host, "www.bbc.co.uk") == 0) { 
        threadData->individual->blackListCount[1] += 1;
        violation(threadData->shared, IPHeader, "bbc");
    }

    free(host);
    free(httpString);
}

void analyseTCP(struct ThreadData* threadData, const struct ip* IPHeader, const uint8_t *Packet, int packetLength) {
    int hs = sizeof(struct tcphdr);
    if (packetLength < hs) {
        return;
    }
    const struct tcphdr* Header = (const struct tcphdr*)Packet;
    hs = 4 * Header->th_off;
    if (Header->th_flags == TH_SYN) {
        threadData->individual->SYNCount += 1;
        addIPv4(threadData->shared->set, *((uint32_t*)&(IPHeader->ip_src)));
    }
    if (ntohs(Header->th_dport) == 80) {
        analyseHTTP(threadData, IPHeader, (const char*)(Packet + hs), packetLength - hs);
    }
}

void analyseIPv4(struct ThreadData* threadData, const uint8_t *Packet, int packetLength) {
    int hs = sizeof(struct ip);
    if (packetLength < hs) {
        return;
    }
    const struct ip* Header = (const struct ip*)Packet;
    hs = 4 * Header->ip_hl;
    switch (Header->ip_p) {
        case IPPROTO_TCP:
            analyseTCP(threadData, Header, Packet + hs, packetLength - hs);
            break;
    }
}

void analyseARP(struct IndividualData* individual, const uint8_t *Packet, int packetLength) {
    int hs = sizeof(struct arphdr);
    if (packetLength < hs) {
        return;
    }
    const struct arphdr* Header = (const struct arphdr*)Packet;
    if (ntohs(Header->ar_op) == ARPOP_REPLY) {
        individual->ARPCount += 1;
    }
    return;
}

void analyse(struct ThreadData* threadData, const struct pcap_pkthdr* PHeader, const uint8_t* Packet) {
    int hs = sizeof(struct ether_header);
    if (PHeader->caplen < hs) {
        return;
    }
    struct ether_header* Header = (struct ether_header*)Packet;
    switch (ntohs(Header->ether_type)) {
        case ETHERTYPE_IP:
            analyseIPv4(threadData, Packet + hs, PHeader->caplen - hs);
            break;
        case ETHERTYPE_ARP:
            analyseARP(threadData->individual, Packet + hs, PHeader->caplen - hs);
            break;
    }
}