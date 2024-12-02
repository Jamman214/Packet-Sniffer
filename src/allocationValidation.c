#include "allocationValidation.h"

#include <stdlib.h>
#include <stdio.h>

// Prints error message and exits if memory allocation fails
void validateAlloc(void* ptr, char* message) {
    if (!ptr) {
        fprintf(stderr, message);
        exit(EXIT_FAILURE);
    }
}