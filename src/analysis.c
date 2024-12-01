#include "analysis.h"

#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h> // ntohs
#include <net/ethernet.h> // ETHERTYPE_IP, ETHERTYPE_ARP
#include <net/if_arp.h> // arphdr, ARPOP_REPLY
#include <netinet/ip.h> // ip
#include <netinet/tcp.h> // tcphdr, TH_SYN
#include <netinet/in.h> // IPPROTO_TCP

// Prints an IPv4 address with correct formatting
void printIPv4(const uint8_t* ip) {
    int i;
    for (i=0; i<4; i++) {
        printf("%d", *(ip+i));
        if (i<3) {
            printf(":");
        }
    }
}

// Prints the specified message for a blacklisted URL
void violation(struct SharedData* shared, const struct ip* IPHeader, char* host) {
    pthread_mutex_lock(&shared->print_lock);
        printf("========================================\n");
        printf("Blacklisted URL violation detected\n");
        printf("Source IP address: ");
        printIPv4((const uint8_t*)&(IPHeader->ip_src));
        printf("\nDestination IP address: ");
        printIPv4((const uint8_t*)&(IPHeader->ip_dst));
        printf(" (");
        printf(host);
        printf(")\n========================================\n");
    pthread_mutex_unlock(&shared->print_lock);
}

// If the packet's destination is blacklisted then increment the count
void analyseHTTP(struct ThreadData* threadData, const struct ip* IPHeader, const char* Packet, int packetLength) {
    char* httpString = (char*)malloc(packetLength + sizeof(char));
    httpString[packetLength] = '\0';
    memcpy(httpString, Packet, packetLength);

    // Find host location in the packet
    char* hostStart = strstr(httpString, "Host: ");
    if (hostStart == NULL) {
        free(httpString);
        return;
    }

    // Get the host
    hostStart += 6;
    const char* hostEnd = strstr(hostStart, "\r\n");
    int hostLen = hostEnd - hostStart;
    char* host = (char*)malloc(hostLen + sizeof(char));
    host[hostLen] = '\0';
    memcpy(host, hostStart, hostLen);

    // If host is blacklisted print message and increment count
    if (strcmp(host, "www.google.co.uk") == 0) {
        threadData->individual->blackListCount[0] += 1;
        violation(threadData->shared, IPHeader, "google");
    } else if (strcmp(host, "www.bbc.co.uk") == 0) { 
        threadData->individual->blackListCount[1] += 1;
        violation(threadData->shared, IPHeader, "bbc");
    }

    // Release memory
    free(host);
    free(httpString);
}

// Checks that packet is long enough to contain a TCP header
// If packet is a SYN packet, increment the count
// If packets destination is port 80, analyse the HTML contents
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

// Checks that packet is long enough to contain an IPv4 header
// If packet is a TCP packet, analyse the TCP contents
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

// Checks that packet is long enough to contain an ARP header
// If packet is an ARP respose, increment the count
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

// Checks that packet is long enough to contain an ethernet header
// Checks protocol used and passes contents to respective function to analyse them
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