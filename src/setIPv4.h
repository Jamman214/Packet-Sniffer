#ifndef CS241_SET_IPV4_H
#define CS241_SET_IPV4_H

#include "stdint.h"

#include <pthread.h>

struct IPv4Set {
    int size;
    int cap;
    pthread_mutex_t lock;
    uint32_t* contents;
};

void initIPv4Set(struct IPv4Set* set, int capacity);

void freeIpv4Set(struct IPv4Set* set);

void addIPv4(struct IPv4Set* set, uint32_t newIPv4);

#endif
