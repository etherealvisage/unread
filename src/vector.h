#ifndef VECTOR_H
#define VECTOR_H

#include <stddef.h>  // for size_t

typedef struct vector_t {
    void *vector;
    size_t alloc, used;
} vector_t;

void init_vector(vector_t *vector);
void free_vector(vector_t *vector);

void add_vector_element(vector_t *vector, char *item, size_t size);
void *add_get_vector_element(vector_t *vector, size_t size);
void pop_vector_element(vector_t *vector);
void preallocate_vector(vector_t *vector, size_t size, size_t count);
void resize_vector(vector_t *vector, size_t size, size_t count);
void clone_vector(vector_t *vector, vector_t *clone, size_t size);

#define VECTOR_TYPE(type)                   vector_t

#define VECTOR_INIT(type, vector)           init_vector(vector)
#define VECTOR_FREE(type, vector)           free_vector(vector)
#define VECTOR_PUSH(type, vector, item)     add_vector_element(vector, (char *)&item, sizeof(type))
#define VECTOR_PUSH_PTR(type, vector, item) add_vector_element(vector, (char *)item, sizeof(type))
#define VECTOR_DATA(type, vec)              ((type *)(vec)->vector)
#define VECTOR_GET(type, vector, i)         (VECTOR_DATA(type, vector)[i])
#define VECTOR_GET_PTR(type, vector, i)     (&VECTOR_DATA(type, vector)[i])
#define VECTOR_GET_SIZE(type, vector)       (vector)->used
#define VECTOR_CLEAR(type, vector)          (vector)->used = 0
#define VECTOR_POP(type, vector)            pop_vector_element(vector)
#define VECTOR_RESERVE(type, vector, count) preallocate_vector(vector, sizeof(type), count)
#define VECTOR_RESIZE(type, vector, count)  resize_vector(vector, sizeof(type), count)
#define VECTOR_GET_BACK_PTR(type, vector)   VECTOR_GET_PTR(type, vector, (vector)->used - 1)
#define VECTOR_CLONE(type, vector, clone)   clone_vector(vector, clone, sizeof(type))

#define VECTOR_FOR_EACH_PTR(type, p, vector) \
    for (type *p = VECTOR_DATA(type, vector); p < VECTOR_DATA(type, vector) \
            + VECTOR_GET_SIZE(type, vector); p ++)

#endif
