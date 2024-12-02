#include "allocationValidation.h"

#include <stdlib.h>
#include <stdio.h>


void validateAlloc(void* ptr, char* message) {
    if (!ptr) {
        fprintf(stderr, message);
        exit(EXIT_FAILURE);
    }
}