#include "setIPv4.h"
#include "allocationValidation.h"

#include <stdlib.h>

// Initialises a set with the given capacity
struct IPv4Set* initIPv4Set(int capacity) {
    uint32_t* contents = (uint32_t*)calloc(capacity, 4);
    validateAlloc(contents, "Unable to allocate memory for set contents");

    struct IPv4Set* set = (struct IPv4Set*)malloc(sizeof(struct IPv4Set));
    validateAlloc(set, "Unable to allocate memory for set");

    set->size = 0;
    set->cap = capacity;
    pthread_mutex_init(&set->lock, NULL);
    set->contents = contents;
    return set;
}

// Releases memory used by sets
void freeIpv4Set(struct IPv4Set* set) {
    free(set->contents);
    free(set);
}

// FNV-1a hash
uint32_t hashIPv4(uint32_t* IPv4) {
    uint32_t hash = 0x811c9dc5;
    int i;
    for (i=0; i<4; i++) {
        hash ^= *((uint8_t*)IPv4 + i);
        hash *= 0x01000193;
    }
    return hash;
}

void addIPv4_(pthread_mutex_t* print_lock, struct IPv4Set* set, uint32_t newIPv4);

// Doubles capacity of the set and rehashes all values
void rehashSet(pthread_mutex_t* print_lock, struct IPv4Set* set) {
    uint32_t* oldContents = set->contents;
    set->cap *= 2;
    set->contents = (uint32_t*)calloc(set->cap, 4);
    validateAllocTS(print_lock, set->contents, "Unable to allocate memory to increase set capacity");

    set->size = 0;
    int i;
    for (i=0; i<set->cap/2; i++) {
        if (*(oldContents+i) != 0) {
            addIPv4_(print_lock, set, *(oldContents+i));
        }
    }
    free(oldContents);
}

// Add new values to set, doubling the size if load factor is too high
void addIPv4_(pthread_mutex_t* print_lock, struct IPv4Set* set, uint32_t newIPv4) {
    uint32_t hash = hashIPv4(&newIPv4);
    uint32_t* ptr = set->contents + (hash % set->cap);
    while (*ptr != 0) {
        if (*ptr == newIPv4) {
            return;
        }
        hash = hashIPv4(&hash);
        ptr = set->contents + (hash % set->cap);
    }
    if (set->size+1 > set->cap/2) {
        rehashSet(print_lock, set);
        addIPv4_(print_lock, set, newIPv4);
        return;
    }
    *ptr = newIPv4;
    set->size += 1;
}

// locks set before adding new value
void addIPv4(pthread_mutex_t* print_lock, struct IPv4Set* set, uint32_t newIPv4) {
    pthread_mutex_lock(&set->lock);
    addIPv4_(print_lock, set, newIPv4);
    pthread_mutex_unlock(&set->lock);
}
