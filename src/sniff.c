#include "sniff.h"
#include "dispatch.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>

pcap_t* pcap_handle;

// Terminates pcap_loop
void signalHandler(int sig) {
    if (pcap_handle != NULL) {
        pcap_breakloop(pcap_handle);
    }
}


// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
    // capturing session. check the man page of pcap_open_live()
    signal(SIGINT, signalHandler);
    pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Unable to open interface %s\n", errbuf);
        exit(EXIT_FAILURE);
    } else {
        printf("SUCCESS! Opened %s for capture\n", interface);
    }

    // Initialise threads, and start packet capture
    int poolSize = 8;
    struct PoolData* threadPool = initPool(poolSize);
    threadPool->shared->verbose = verbose;
    pcap_loop(pcap_handle, -1, dispatch, (u_char*)threadPool->shared);
    // Release handle
    pcap_close(pcap_handle);

    // Tell threads to terminate
    pthread_mutex_lock(&threadPool->shared->terminate_lock);
    threadPool->shared->terminate = 1;
    pthread_cond_signal(&threadPool->shared->queue.cond);
    pthread_mutex_unlock(&threadPool->shared->terminate_lock);

    // Collect data from terminated threads
    int SYNCount = 0;
    int ARPCount = 0;
    int blackListCount[2] = {0,0};
    struct IPv4Set* IPs = initIPv4Set(4);
    struct IndividualData* data = threadPool->threads;
    int i;
    for (i=0; i<poolSize; i++) {
        pthread_join(data->threadID, NULL);
        SYNCount += data->SYNCount;
        ARPCount += data->ARPCount;
        blackListCount[0] += data->blackListCount[0];
        blackListCount[1] += data->blackListCount[1];
        freeListIntoSet(&data->IPs, IPs);
        data += 1;
    }

    // Output results
    printf("\n%d SYN packets detected from %d different IPs (syn attack)\n", SYNCount, IPs->size);
    printf("%d ARP responses (cache poisoning)\n", ARPCount);
    printf("%d URL Blacklist violations (%d google and %d bbc)\n", blackListCount[0]+blackListCount[1], blackListCount[0], blackListCount[1]);

    // Release all memory
    freePoolData(threadPool);
    freeIpv4Set(IPs);
    exit(0);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
    unsigned int i;
    static unsigned long pcount = 0;
    // Decode Packet Header
    struct ether_header *eth_header = (struct ether_header *) data;
    printf("\n\n === PACKET %ld HEADER ===", pcount);
    printf("\nSource MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_shost[i]); //a->b = (*a).b
        if (i < 5) {
            printf(":");
        }
    }
    printf("\nDestination MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_dhost[i]);
        if (i < 5) {
            printf(":");
        }
    }
    printf("\nType: %hu\n", eth_header->ether_type);
    printf(" === PACKET %ld DATA == \n", pcount);
    // Decode Packet Data (Skipping over the header)
    int data_bytes = length - ETH_HLEN;
    const unsigned char *payload = data + ETH_HLEN;
    const static int output_sz = 20; // Output this many bytes at a time
    while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
        if (i < output_bytes) {
            printf("%02x ", payload[i]);
        } else {
            printf ("   "); // Maintain padding for partial lines
        }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
        char byte = payload[i];
        if (byte > 31 && byte < 127) {
            // Byte is in printable ascii range
            printf("%c", byte);
        } else {
            printf(".");
        }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
    }
    pcount++;
}
