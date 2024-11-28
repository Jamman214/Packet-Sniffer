#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include "dispatch.h"

pcap_t* pcap_handle;
struct ThreadGroup* threadGroup;

void breakCapture(int sig) {
    if (pcap_handle != NULL) {
        pcap_breakloop(pcap_handle);
    }
}


// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
    // capturing session. check the man page of pcap_open_live()
    signal(SIGINT, breakCapture);
    pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Unable to open interface %s\n", errbuf);
        exit(EXIT_FAILURE);
    } else {
        printf("SUCCESS! Opened %s for capture\n", interface);
    }


    // struct pcap_pkthdr header; // Packet header structure
    // const unsigned char *packet; // Rest of the packet data

    // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
    // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
    // See the man pages of both pcap_loop() and pcap_next().

    // while (1) {
    // Capture a  packet
    // packet = pcap_next(pcap_handle, &header);
    // if (packet == NULL) {
    //     // pcap_next can return null if no packet is seen within a timeout
    //     if (verbose) {
    //         printf("No packet received. %s\n", pcap_geterr(pcap_handle));
    //     }
    // } else {
    //     // If verbose is set to 1, dump raw packet to terminal
    //     if (verbose) {
    //         dump(packet, header.len);
    //     }
    //     // Dispatch packet for processing
    //     dispatch(&header, packet, verbose);
    // }



    // if (terminated) {
    //   if (pcap_handle != NULL) {
    //       pcap_close(pcap_handle);
    //   }
    //   exit(0);
    // }
    // }
    // pcap_loop(pcap_handle, -1, dispatch, (u_char*)&verbose);

    threadGroup = getThreadGroup();
    initThreads();
    pcap_loop(pcap_handle, -1, dispatch, NULL);
    pcap_close(pcap_handle);
    pthread_mutex_lock(threadGroup->terminate_lock);
    *threadGroup->terminate = 1;
    pthread_mutex_unlock(threadGroup->terminate_lock);
    pthread_cond_broadcast(&threadGroup->queue->cond);
    pthread_mutex_t* PRINT_LOCK = get_PRINT_LOCK();
    int SYNCount = 0;
    int ARPCount = 0;
    int blackListCount[2] = {0,0};
    printf("\n");
    struct ThreadData* data;
    int i;
    for (i=0; i<POOLSIZE; i++) {
        data = threadGroup->pool+i;
        pthread_join(data->threadID, NULL);
        pthread_mutex_lock("PRINT_LOCK");
            printf("Cleaned thread %d\n", i);
        pthread_mutex_lock("PRINT_LOCK");
        SYNCount += data->SYNCount;
        ARPCount += data->ARPCount;
        blackListCount[0] += data->blackListCount[0];
        blackListCount[1] += data->blackListCount[1];
    }
    free(threadGroup);
    printf("%d SYN packets detected from UNKNOWN different IPs (syn attack)\n", SYNCount);
    printf("%d ARP responses (cache poisoning)\n", ARPCount);
    printf("%d URL Blacklist violations (%d google and %d bbc)\n", blackListCount[0]+blackListCount[1], blackListCount[0], blackListCount[1]);
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
