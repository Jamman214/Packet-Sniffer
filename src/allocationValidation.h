#include <pthread.h>

void validateAlloc(void* ptr, char* message);

void validateAllocTS(pthread_mutex_t* print_lock, void* ptr, char* message);