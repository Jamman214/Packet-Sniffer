#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include <pthread.h>

#define POOLSIZE 4

struct ThreadData {
    pthread_t threadID;
    int SYNCount;
    int ARPCount;
    int blackListCount[2];
};

// Stores arguments to be passed to analysePhysical
struct ThreadArgs {
    struct pcap_pkthdr *header;
    u_char *packet;
};

// Stores threadArgs
struct WorkQueue {
    struct WorkQueueElement* head;
    struct WorkQueueElement* tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct WorkQueueElement {
    struct ThreadArgs* threadArgs;
    struct WorkQueueElement* next;
};

struct ThreadGroup {
    struct WorkQueue* queue;
    struct ThreadData* pool;
    pthread_mutex_t* terminate_lock;
    int* terminate;
};



// void dispatch(struct pcap_pkthdr *header, 
//               const unsigned char *packet, 
//               int verbose);

void dispatch(u_char *args, 
              const struct pcap_pkthdr *header, 
              const u_char *packet);

void initThreads();

void closeThreads();

struct ThreadGroup* getThreadGroup();

pthread_mutex_t* get_PRINT_LOCK();

#endif
