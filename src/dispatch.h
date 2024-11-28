#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include <pthread.h>

#define POOLSIZE 4

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

struct IPv4Set {
    int size;
    int cap;
    pthread_mutex_t lock;
    uint32_t* contents;
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




// struct ThreadData {
//     pthread_t threadID;
//     int SYNCount;
//     int ARPCount;
//     int blackListCount[2];
// };

// struct ThreadMaterials {
//     struct ThreadData* threadData;
//     pthread_mutex_t* PRINT_LOCK;
//     struct IPv4Set* set;
// };

// struct IPv4Set {
//     int size;
//     int cap;
//     pthread_mutex_t lock;
//     uint32_t* contents;
// };

// // Stores arguments to be passed to analysePhysical
// struct ThreadArgs {
//     struct pcap_pkthdr *header;
//     u_char *packet;
// };

// // Stores threadArgs
// struct WorkQueue {
//     struct WorkQueueElement* head;
//     struct WorkQueueElement* tail;
//     pthread_mutex_t lock;
//     pthread_cond_t cond;
// };

// struct WorkQueueElement {
//     struct ThreadArgs* threadArgs;
//     struct WorkQueueElement* next;
// };

// struct ThreadGroup {
//     struct WorkQueue* queue;
//     struct ThreadData* pool;
//     struct IPv4Set* set;
//     pthread_mutex_t* terminate_lock;
//     int* terminate;
// };

// void dispatch(struct pcap_pkthdr *header, 
//               const unsigned char *packet, 
//               int verbose);

void dispatch(u_char *args, 
              const struct pcap_pkthdr *header, 
              const u_char *packet);


// void closeThreads();

// struct ThreadGroup* getThreadGroup();

// pthread_mutex_t* get_PRINT_LOCK();

void freePoolData();

struct PoolData* initPool();

void addIPv4(struct IPv4Set* set, uint32_t newAddress);

#endif
