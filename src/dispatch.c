#include "dispatch.h"
#include "analysis.h"
#include "sniff.h"
#include "allocationValidation.h"

#include <stdlib.h>
#include <string.h>



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Struct initialisers
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Allocates memory to and creates the work queue
struct WorkQueue* initWorkQueue () {
    struct WorkQueue* queue = (struct WorkQueue*)calloc(1, sizeof(struct WorkQueue));
    validateAlloc(queue, "Unable to allocate memory for work queue\n");
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->cond, NULL);
    return queue;
}

// Allocates memory to and creates an element for the work queue
struct WorkQueueElement* initWorkQueueElement(pthread_mutex_t* print_lock, struct PacketData* packetData) {
    struct WorkQueueElement* element = (struct WorkQueueElement*)malloc(sizeof(struct WorkQueueElement));
    validateAllocTS(print_lock, element, "Unable to allocate memory for work queue element\n");

    element->packetData = packetData;
    element->next = NULL;
    return element;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Work dispatcher
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Adds an element to the work queue (Thread safe)
void enqueue(pthread_mutex_t* print_lock, struct WorkQueue* queue, struct PacketData* packetData) {
    struct WorkQueueElement* element = initWorkQueueElement(print_lock, packetData);
    pthread_mutex_lock(&queue->lock);
        if (queue->head == NULL) {
            queue->head = element;
        } else {
            queue->tail->next = element;
        }
        queue->tail = element;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);
}

// Copies the header and packet, since their memory will not be accessible after this function ends
// Enqueues packet data
void dispatch(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct SharedData* shared = (struct SharedData*)args;

    struct pcap_pkthdr* headerCopy = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
    validateAllocTS(&shared->print_lock, headerCopy, "Unable to allocate memory for header copy\n");
    memcpy((void*)headerCopy, (void*)header, sizeof(struct pcap_pkthdr));

    u_char* packetCopy = (u_char*)malloc(header->caplen);
    validateAllocTS(&shared->print_lock, packetCopy, "Unable to allocate memory for packet copy\n");
    memcpy((void*)packetCopy, (void*)packet, header->caplen);

    struct PacketData* packetData = (struct PacketData*)malloc(sizeof(struct PacketData));
    validateAllocTS(&shared->print_lock, packetData, "Unable to allocate memory for packet data structure\n");

    packetData->header = headerCopy;
    packetData->packet = packetCopy;
    enqueue(&shared->print_lock, shared->queue, packetData);
    if (shared->verbose) {
        pthread_mutex_lock(&shared->print_lock);
        dump(packet, header->len);
        pthread_mutex_unlock(&shared->print_lock);
    }
    
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Threads
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Releases memory for a packet 
void freePacketData(struct PacketData* packetData) {
    free(packetData->header);
    free(packetData->packet);
    free(packetData);
}

// Repeatedly removes an element from the queue if one exists, or waits until signalled if queue is empty
// Terminates when terminate flag is set
void* collect(void* arg) {
    struct ThreadData* threadData = (struct ThreadData*)arg;
    struct PacketData* packetData = NULL;
    struct WorkQueueElement* element = NULL;

    while (1) {
        // Dequeue element from work queue
        pthread_mutex_lock(&threadData->shared->queue->lock);
            
            // Wait till queue contains an element, awake when signalled
            while (threadData->shared->queue->head == NULL) {
                // If the program terminates, release locks and signal so another thread can continue
                pthread_mutex_lock(&threadData->shared->terminate_lock);
                    if (threadData->shared->terminate) {
                        pthread_mutex_unlock(&threadData->shared->terminate_lock);
                        pthread_cond_signal(&threadData->shared->queue->cond);
                        pthread_mutex_unlock(&threadData->shared->queue->lock);
                        free(threadData);
                        return NULL;
                    }
                pthread_mutex_unlock(&threadData->shared->terminate_lock);

                pthread_cond_wait(&threadData->shared->queue->cond, &threadData->shared->queue->lock);
            }
            
            element = threadData->shared->queue->head;
            threadData->shared->queue->head = threadData->shared->queue->head->next;
        pthread_cond_signal(&threadData->shared->queue->cond);
        pthread_mutex_unlock(&threadData->shared->queue->lock);

        // Analyse dequeued packet
        packetData = element->packetData;
        analyse(threadData, packetData->header, packetData->packet);

        // Release memory
        free(element);
        freePacketData(packetData);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Thread Pool
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Allocates memory for pool structures
// Initialises structures
// Creates threads and passes necessary data to them
struct PoolData* initPool(int poolSize) {
    struct PoolData* pool = (struct PoolData*)malloc(sizeof(struct PoolData));
    validateAlloc(pool, "Unable to allocate memory for pool data structure\n");

    struct IndividualData* threads = (struct IndividualData*)calloc(poolSize, sizeof(struct IndividualData));
    validateAlloc(threads, "Unable to allocate memory for threads data structure\n");

    struct SharedData* shared = (struct SharedData*)malloc(sizeof(struct SharedData));
    validateAlloc(shared, "Unable to allocate memory for shared data structure\n");

    shared->queue = initWorkQueue();
    shared->set = initIPv4Set(4);
    pthread_mutex_init(&shared->terminate_lock, NULL);
    shared->terminate = 0;
    pthread_mutex_init(&shared->print_lock, NULL); 

    int i;
    for (i=0; i<poolSize; i++) {
        struct ThreadData* threadData = (struct ThreadData*)malloc(sizeof(struct ThreadData));
        validateAllocTS(&shared->print_lock, threadData, "Unable to allocate memory for individual thread data structure\n");

        threadData->individual = threads+i;
        threadData->shared = shared;
        pthread_create((pthread_t *)threadData->individual, NULL, collect, (void*)threadData);
    }

    pool->threads = threads;
    pool->shared = shared;
    return pool;
}

// Releases memory for thread pool
void freePoolData(struct PoolData* pool) {
    free(pool->threads);
    free(pool->shared->queue);
    freeIpv4Set(pool->shared->set);
    free(pool->shared);
    free(pool);
}