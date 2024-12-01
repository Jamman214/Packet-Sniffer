#include "allocationValidation.h"

#include <stdlib.h>
#include <stdio.h>


void validateAlloc(void* ptr, char* message) {
    if (!ptr) {
        fprintf(stderr, message);
        exit(EXIT_FAILURE);
    }
}


void validateAllocTS(pthread_mutex_t* print_lock, void* ptr, char* message) {
    if (!ptr) {
        pthread_mutex_lock(print_lock);
            fprintf(stderr, message);
        pthread_mutex_unlock(print_lock);
        exit(EXIT_FAILURE);
    }
}