#include "analysis.h"

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
//#include <netinet/ethertype.h>

#define TCP 0x06
#define IP 0x0800
#define ARP 0x0806
#define SYN 0x02


// void analyse(struct pcap_pkthdr *header, const uint8_t *packet, int verbose) {
// }

debug = 0;
int count = 0;

void printIP(const uint8_t* ip) {
    int i;
    for (i=0; i<4; i++) {
        printf("%d", *(ip+i));
        if (i<3) {
            printf(":");
        }
    }
}

void violation(const struct ip* IPHeader, char* host) {
    printf("========================================\n");
    printf("Blacklisted URL violation detected\n");
    printf("Source IP address: ");
    printIP((const uint8_t*)&(IPHeader->ip_src));
    printf("\nDestination IP address: ");
    printIP((const uint8_t*)&(IPHeader->ip_dst));
    printf(" (");
    printf(host);
    printf(")\n========================================\n");
}

void analyseHTTP(const struct ip* IPHeader, const unsigned char* Packet, int packetLength) {
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
        violation(IPHeader, "google");
    } else if (strcmp(host, "www.bbc.co.uk") == 0) { 
        violation(IPHeader, "bbc");
    }

    if (debug) {
        printf("========================================\n");
        printf(host);
        printf("========================================\n");
        printf(httpString);
        printf("========================================\n");
    }

    free(host);
    free(httpString);
}



void analyseTCP(const struct ip* IPHeader, const uint8_t *Packet, int packetLength) {
    const struct tcphdr* Header = (const struct tcphdr*)Packet;
    if (Header->th_flags == SYN) {
        count ++;
    }
    const int headerLength = (Header->th_off) * 4;
    if (ntohs(Header->th_dport) == 80) {
        analyseHTTP(IPHeader, (Packet + headerLength), packetLength-headerLength);
    }
}

void analyseIPv4(const uint8_t *Packet, int packetLength) {
    const struct ip* Header = (const struct ip*)Packet;
    switch (Header->ip_p) {
        case TCP:
            analyseTCP(Header, Packet + 4 * (Header->ip_hl), packetLength - 4 * (Header->ip_hl));
            break;
    }
}

void analyseARP() {
    if (debug) printf("Detected ARP\n");
}

void analysePhysical(struct pcap_pkthdr *PHeader, const uint8_t *Packet, int verbose) {
    const struct ether_header* Header = (const struct ether_header*)Packet;
    switch (ntohs(Header->ether_type)) {
        case IP:
            analyseIPv4(Packet + 14, PHeader->len - 14);
            break;
        case ARP:
            analyseARP();
            break;
    }
}