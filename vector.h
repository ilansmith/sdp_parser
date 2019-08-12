#ifndef _VECTOR_H_
#define _VECTOR_H_

#include <stdarg.h>

typedef void *vector_t;
typedef void (*vec_dtor)(void *e);

vector_t vec_init(vec_dtor dtor);
void vec_uninit(vector_t vector);

int vec_push_back(vector_t vector, void *e);
int vec_insert(vector_t vector, void *e, unsigned int pos);
void vec_erase(vector_t vector, int pos);
void *vec_at(vector_t vector, int pos);
unsigned int vec_size(vector_t vector);
unsigned int vec_capacity(vector_t vector);
unsigned int vec_for_each(vector_t vector, int (func)(void *e, va_list va), ...);
void **vec_idx2addr(vector_t vector, unsigned int idx);

#define VEC_OFFSET(vector, iter) \
	((unsigned int)(iter - (typeof(iter))vec_idx2addr(vector, 0)))

#define VEC_FOREACH(vector, iter) \
	for (iter = (typeof(iter))vec_idx2addr(vector, 0); \
		VEC_OFFSET(vector, iter) < vec_size(vector); \
		iter++)
#endif

