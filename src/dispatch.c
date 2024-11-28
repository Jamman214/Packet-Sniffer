#include "dispatch.h"

#include <pcap.h>

#include "analysis.h"
#include "stdint.h"

#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

// void dispatch(struct pcap_pkthdr *header,
//               const unsigned char *packet,
//               int verbose) {
//   // TODO: Your part 2 code here
//   // This method should handle dispatching of work to threads. At present
//   // it is a simple passthrough as this skeleton is single-threaded.
//   analyse(header, packet, verbose);
// }


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Struct initialisers
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


struct WorkQueue* initWorkQueue () {
    struct WorkQueue* queue = (struct WorkQueue*)calloc(1, sizeof(struct WorkQueue));
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->cond, NULL);
    return queue;
}

struct WorkQueueElement* initWorkQueueElement(struct ThreadArgs* threadArgs) {
    struct WorkQueueElement* element = (struct WorkQueueElement*)malloc(sizeof(struct WorkQueueElement));
    element->threadArgs = threadArgs;
    element->next = NULL;
    return element;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Work dispatcher
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void enqueue(struct WorkQueue* queue, struct ThreadArgs* threadArgs) {
    struct WorkQueueElement* element = initWorkQueueElement(threadArgs);
    pthread_mutex_lock(&queue->lock);
        if (queue->head == NULL) {
            queue->head = element;
        } else {
            queue->tail->next = element;
        }
    pthread_mutex_unlock(&queue->lock);
    pthread_cond_signal(&queue->cond);
    queue->tail = element;
}

void dispatch(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct pcap_pkthdr* headerCopy = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
    memcpy((void*)headerCopy, (void*)header, sizeof(struct pcap_pkthdr));
    u_char* packetCopy = (u_char*)malloc(header->len);
    memcpy((void*)packetCopy, (void*)packet, header->len);
    struct ThreadArgs* threadArgs = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
    threadArgs->header = headerCopy;
    threadArgs->packet = packetCopy;
    enqueue((struct WorkQueue*)args, threadArgs);
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Threads
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void freeThreadArgs(struct ThreadArgs* threadArgs) {
    free(threadArgs->header);
    free(threadArgs->packet);
    free(threadArgs);
}

void* collect(void* arg) {
    int terminated = 0;
    struct ThreadData* threadData = (struct ThreadData*)arg;

    struct ThreadArgs* threadArgs = NULL;
    struct WorkQueueElement* element = NULL;

    while (!terminated) {
        pthread_mutex_lock(&threadData->shared->queue->lock);
            // Hold while the queue is empty
            while (threadData->shared->queue->head == NULL) {
                pthread_cond_wait(&threadData->shared->queue->cond, &threadData->shared->queue->lock);

                // If the program terminates, release locks and broadcast so another thread can continue
                pthread_mutex_lock(&threadData->shared->terminate_lock);
                    if (threadData->shared->terminate) {
                        pthread_mutex_unlock(&threadData->shared->terminate_lock);
                        pthread_mutex_unlock(&threadData->shared->queue->lock);
                        pthread_cond_broadcast(&threadData->shared->queue->cond);
                        return NULL;
                    }
                pthread_mutex_unlock(&threadData->shared->terminate_lock);
            }
            
            element = threadData->shared->queue->head;
            threadData->shared->queue->head = threadData->shared->queue->head->next;
        pthread_mutex_unlock(&threadData->shared->queue->lock);
        pthread_cond_broadcast(&threadData->shared->queue->cond);

        threadArgs = element->threadArgs;
        analyse(threadData, threadArgs->header, threadArgs->packet);

        free(element);
        freeThreadArgs(threadArgs);
    }
    return NULL;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Set
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct IPv4Set* initIPv4Set_(int capacity) {
    uint32_t* contents = (uint32_t*)calloc(capacity, 4);
    struct IPv4Set* set = (struct IPv4Set*)malloc(sizeof(struct IPv4Set));
    set->size = 0;
    set->cap = capacity;
    pthread_mutex_init(&set->lock, NULL);
    set->contents = contents;
    return set;
}

struct IPv4Set* initIPv4Set() {
    return initIPv4Set_(4);
}

void freeIpv4Set(struct IPv4Set* set) {
    free(set->contents);
    free(set);
}

// FNV-1a hash
uint32_t hashIPv4(uint32_t* IPv4) {
    uint32_t hash = 0x811c9dc5;
    int i;
    for (i=0; i<4; i++) {
        hash ^= *((uint8_t*)IPv4+i) && 0xFF;
        hash *= 0x01000193;
    }
    return hash;
}

void addIPv4(struct IPv4Set* set, uint32_t newAddress);

void rehashSet(struct IPv4Set* set) {
    set->cap *= 2;
    uint32_t* oldContents = set->contents;
    set->contents = (uint32_t*)malloc(set->cap * 4);
    set->size = 0;
    int i;
    for (i=0; i<set->cap/2; i++) {
        if (*(oldContents+i) != 0) {
            addIPv4(set, *(oldContents+i));
        }
    }
    free(set->contents);
}

void addIPv4(struct IPv4Set* set, uint32_t newAddress) {
    uint32_t hash = hashIPv4(&newAddress);
    pthread_mutex_lock(&set->lock);
    uint32_t* address = set->contents + (hash % set->cap);
    int i = 0;
    while (*address != 0) {
        hash = hashIPv4(&hash);
        address = set->contents + (hash % set->cap);
    }
    if (*address == newAddress) {
        return;
    }
    if (set->cap+1 > set->cap/2) {
        rehashSet(set);
        addIPv4(set, newAddress);
    }
    *address = newAddress;
    set->size += 1;
    pthread_mutex_unlock(&set->lock);
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Thread Pool
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct PoolData* initPool(int poolSize) {
    struct PoolData* pool = (struct PoolData*)malloc(sizeof(struct PoolData));
    struct IndividualData* threads = (struct IndividualData*)calloc(poolSize, sizeof(struct IndividualData));
    struct SharedData* shared = (struct SharedData*)malloc(sizeof(struct SharedData));
    shared->queue = initWorkQueue();
    shared->set = initIPv4Set();
    pthread_mutex_init(&shared->terminate_lock, NULL);
    shared->terminate = 0;
    pthread_mutex_init(&shared->print_lock, NULL);

    int i;
    for (i=0; i<POOLSIZE; i++) {
        struct ThreadData* threadData = (struct ThreadData*)malloc(sizeof(struct ThreadData));
        threadData->individual = threads+i;
        threadData->shared = shared;
        pthread_create(threads+i, NULL, collect, (void*)threadData);
        printf("Init Thread: %d\n", i);
    }

    return pool;
}

void freePoolData(struct PoolData* pool) {
    free(pool->threads);
    free(pool->shared->queue);
    freeIpv4Set(pool->shared->set);
    free(pool->shared);
    free(pool);
}