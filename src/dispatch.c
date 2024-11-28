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

struct WorkQueue QUEUE = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};
struct ThreadData POOL[POOLSIZE];
pthread_mutex_t TERMINATE_LOCK = PTHREAD_MUTEX_INITIALIZER;
int TERMINATE = 0;
pthread_mutex_t PRINT_LOCK = PTHREAD_MUTEX_INITIALIZER;

struct ThreadGroup* getThreadGroup() {
    struct ThreadGroup* threadGroup = (struct ThreadGroup*)malloc(sizeof(struct ThreadGroup));
    threadGroup->queue = &QUEUE;
    threadGroup->pool = POOL;
    threadGroup->terminate_lock = &TERMINATE_LOCK;
    threadGroup->terminate = &TERMINATE;
    return threadGroup;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Struct initialisers
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct WorkQueueElement* WorkQueueElement(struct ThreadArgs* threadArgs) {
    struct WorkQueueElement* element = (struct WorkQueueElement*)malloc(sizeof(struct WorkQueueElement));
    element->threadArgs = threadArgs;
    element->next = NULL;
    return element;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Work dispatcher
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void enqueue(struct ThreadArgs* threadArgs) {
    struct WorkQueueElement* element = WorkQueueElement(threadArgs);
    pthread_mutex_lock(&QUEUE.lock);
        if (QUEUE.head == NULL) {
            QUEUE.head = element;
        } else {
            QUEUE.tail->next = element;
        }
    pthread_mutex_unlock(&QUEUE.lock);
    pthread_cond_signal(&QUEUE.cond);
    QUEUE.tail = element;
}

void dispatch(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct pcap_pkthdr* headerCopy = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
    memcpy((void*)headerCopy, (void*)header, sizeof(struct pcap_pkthdr));
    u_char* packetCopy = (u_char*)malloc(header->len);
    memcpy((void*)packetCopy, (void*)packet, header->len);
    struct ThreadArgs* threadArgs = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
    threadArgs->header = headerCopy;
    threadArgs->packet = packetCopy;
    enqueue(threadArgs);
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Threads
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void* collect(void* arg) {
    int terminated = 0;
    struct ThreadData* threadData = (struct ThreadData*)arg;
    struct ThreadArgs* threadArgs = NULL;
    struct WorkQueueElement* element = NULL;
    while (!terminated) {
        pthread_mutex_lock(&QUEUE.lock);
            while (QUEUE.head == NULL && !terminated) {
                pthread_cond_wait(&QUEUE.cond, &QUEUE.lock);
                pthread_mutex_lock(&TERMINATE_LOCK);
                    terminated = TERMINATE;
                pthread_mutex_unlock(&TERMINATE_LOCK);
            }
            element = QUEUE.head;
            if (element == NULL) {
                pthread_mutex_unlock(&QUEUE.lock);
                pthread_cond_broadcast(&QUEUE.cond);
                break;
            }
            QUEUE.head = QUEUE.head->next;
        pthread_mutex_unlock(&QUEUE.lock);
        pthread_cond_broadcast(&QUEUE.cond);
        threadArgs = element->threadArgs;
        free(element);
        analyse(&PRINT_LOCK, threadData, threadArgs->header, threadArgs->packet);
        free(threadArgs->header);
        free(threadArgs->packet);
        free(threadArgs);
    }
    return NULL;
}


void initThreads() {
    int i;
    for (i=0; i<POOLSIZE; i++) {
        pthread_create(&POOL[i].threadID, NULL, collect, (void*)&POOL[i]);
        printf("Init Thread: %d\n", i);
    }
}