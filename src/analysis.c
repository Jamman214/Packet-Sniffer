#include "analysis.h"
#include "dispatch.h"

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define TCP 0x06
#define IP 0x0800
#define ARP 0x0806
#define SYN 0x02

// void analyse(struct pcap_pkthdr *header, const uint8_t *packet, int verbose) {
// }

int debug = 0;

void printIP(const uint8_t* ip) {
    int i;
    for (i=0; i<4; i++) {
        printf("%d", *(ip+i));
        if (i<3) {
            printf(":");
        }
    }
}

void violation(pthread_mutex_t* PRINT_LOCK, const struct ip* IPHeader, char* host) {
    pthread_mutex_unlock(PRINT_LOCK);
        printf("========================================\n");
        printf("Blacklisted URL violation detected\n");
        printf("Source IP address: ");
        printIP((const uint8_t*)&(IPHeader->ip_src));
        printf("\nDestination IP address: ");
        printIP((const uint8_t*)&(IPHeader->ip_dst));
        printf(" (");
        printf(host);
        printf(")\n========================================\n");
    pthread_mutex_unlock(PRINT_LOCK);
}

void analyseHTTP(pthread_mutex_t* PRINT_LOCK, struct ThreadData* threadData, const struct ip* IPHeader, const char* Packet, int packetLength) {
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
        threadData->blackListCount[0] += 1;
        violation(PRINT_LOCK, IPHeader, "google");
    } else if (strcmp(host, "www.bbc.co.uk") == 0) { 
        threadData->blackListCount[1] += 1;
        violation(PRINT_LOCK, IPHeader, "bbc");
    }

    free(host);
    free(httpString);
}

void analyseTCP(pthread_mutex_t* PRINT_LOCK, struct ThreadData* threadData, const struct ip* IPHeader, const uint8_t *Packet, int packetLength) {
    const struct tcphdr* Header = (const struct tcphdr*)Packet;
    if (Header->th_flags == SYN) {
        threadData->SYNCount += 1;
    }
    const int headerLength = (Header->th_off) * 4;
    if (ntohs(Header->th_dport) == 80) {
        analyseHTTP(PRINT_LOCK, threadData, IPHeader, (const char*)(Packet + headerLength), packetLength-headerLength);
    }
}

void analyseIPv4(pthread_mutex_t* PRINT_LOCK, struct ThreadData* threadData, const uint8_t *Packet, int packetLength) {
    const struct ip* Header = (const struct ip*)Packet;
    switch (Header->ip_p) {
        case TCP:
            analyseTCP(PRINT_LOCK, threadData, Header, Packet + 4 * (Header->ip_hl), packetLength - 4 * (Header->ip_hl));
            break;
    }
}

void analyseARP(struct ThreadData* threadData) {
    threadData->ARPCount += 1;
    return;
}

void analyse(pthread_mutex_t* PRINT_LOCK, struct ThreadData* threadData, const struct pcap_pkthdr* PHeader, const uint8_t* Packet) {
    struct ether_header* Header = (struct ether_header*)Packet;
    switch (ntohs(Header->ether_type)) {
        case IP:
            analyseIPv4(PRINT_LOCK, threadData, Packet + 14, PHeader->len - 14);
            break;
        case ARP:
            analyseARP(threadData);
            break;
    }
}