#include <stdlib.h>  // for realloc, free
#include <string.h>  // for memcpy
#include "vector.h"

#define INITIAL_VECTOR_SIZE 8

void init_vector(vector_t *vector) {
    vector->vector = 0;
    vector->alloc = vector->used = 0;
}

void free_vector(vector_t *vector) {
    free(vector->vector);
    vector->vector = 0;
    vector->alloc = vector->used = 0;
}

void add_vector_element(vector_t *vector, char *item, size_t size) {
    if(vector->used >= vector->alloc) {
        vector->alloc
            = (vector->alloc ? vector->alloc * 2 : INITIAL_VECTOR_SIZE);
        vector->vector = realloc(vector->vector, vector->alloc * size);
    }
    
    memcpy((char *)vector->vector + vector->used * size, item, size);
    
    vector->used ++;
}

void *add_get_vector_element(vector_t *vector, size_t size) {
    if(vector->used >= vector->alloc) {
        vector->alloc
            = (vector->alloc ? vector->alloc * 2 : INITIAL_VECTOR_SIZE);
        vector->vector = realloc(vector->vector, vector->alloc * size);
    }
    
    return (char *)vector->vector + (vector->used++ * size);
}

void pop_vector_element(vector_t *vector) {
    if(vector->used > 0) {
        vector->used --;
    }
}

void preallocate_vector(vector_t *vector, size_t size, size_t count) {
    if(vector->alloc < count) {
        vector->alloc = count;
        vector->vector = realloc(vector->vector, vector->alloc * size);
    }
}

void resize_vector(vector_t *vector, size_t size, size_t count) {
    preallocate_vector(vector, size, count);
    vector->used = count;
}

void clone_vector(vector_t *vector, vector_t *clone, size_t size) {
    preallocate_vector(clone, size, vector->alloc);
    memcpy(clone->vector, vector->vector, vector->alloc * size);
    clone->used = vector->used;
}
