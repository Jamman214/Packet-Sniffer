#include "LListArray32.h"
#include "allocationValidation.h"
#include "setIPv4.h"
#include <stdlib.h>

// Initialises a new node
struct LListArrayNode32* initLListArrayNode32(int capacity) {
    uint32_t* elements = (uint32_t*)malloc(capacity * sizeof(uint32_t));
    validateAlloc(elements, "Unable to allocate memory for linked list array node elements");

    struct LListArrayNode32* node = (struct LListArrayNode32*)calloc(1, sizeof(struct LListArrayNode32));
    validateAlloc(node, "Unable to allocate memory for linked list array node");

    node->cap = capacity;
    node->elements = elements;
    return node;
}

// Initialises the list
void initLListArray32(struct LListArray32* list) {
    list->head = initLListArrayNode32(4);
    list->tail = list->head;
}

// Inserts an element into the list, and doubles the size if already full
void addLListArray32(struct LListArray32* list, uint32_t element) {
    if (list->tail->size == list->tail->cap) {
        list->tail->next = initLListArrayNode32(list->tail->cap * 2);
        list->tail = list->tail->next;
    }
    list->tail->elements[list->tail->size] = element;
    list->tail->size += 1;
}

// Frees data used by list and adds every element into the set
void freeListIntoSet(struct LListArray32* list, struct IPv4Set* set) {
    struct LListArrayNode32* node = list->head;
    struct LListArrayNode32* nextNode;
    int i;
    while (node != NULL) {
        for (i=0; i<node->size; i++) {
            addIPv4(set, node->elements[i]);
        }
        nextNode = node->next;
        free(node->elements);
        free(node);
        node = nextNode;
    }
}