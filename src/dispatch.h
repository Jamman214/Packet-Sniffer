#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include "set_IPv4.h"
#include "stdint.h"

#include <pcap.h>
#include <pthread.h>

struct WorkQueue {
    struct WorkQueueElement* head;
    struct WorkQueueElement* tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct ThreadArgs {
    struct pcap_pkthdr *header;
    u_char *packet;
};

struct WorkQueueElement {
    struct ThreadArgs* threadArgs;
    struct WorkQueueElement* next;
};

struct IndividualData {
    pthread_t threadID;
    int SYNCount;
    int ARPCount;
    int blackListCount[2];
};

struct SharedData {
    struct WorkQueue* queue;
    struct IPv4Set* set;
    pthread_mutex_t terminate_lock;
    int terminate;
    pthread_mutex_t print_lock;
};

struct ThreadData {
    struct IndividualData* individual;
    struct SharedData* shared;
};

struct PoolData {
    struct IndividualData* threads;
    struct SharedData* shared;
};

void dispatch(u_char *args, 
              const struct pcap_pkthdr *header, 
              const u_char *packet);

void freePoolData();

struct PoolData* initPool();

void addIPv4(struct IPv4Set* set, uint32_t newAddress);

#endif
