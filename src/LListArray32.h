#ifndef CS241_ALLOCATION_VALIDATION_32_H
#define CS241_ALLOCATION_VALIDATION_32_H

#include "stdint.h"
#include "setIPv4.h"


struct LListArrayNode32 {
    struct LListArrayNode32* next;
    int size;
    int cap;
    uint32_t* elements;
};

struct LListArray32 {
    struct LListArrayNode32* head;
    struct LListArrayNode32* tail;
};

void initLListArray32(struct LListArray32* list);

void addLListArray32(struct LListArray32* list, uint32_t element);

void makeSet(struct LListArray32* list, struct IPv4Set* set);

void freeListIntoSet(struct LListArray32* list, struct IPv4Set* set);

#endif

