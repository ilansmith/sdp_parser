#ifndef _UTIL_H_
#define _UTIL_H_

/*
 * struct code2code {
 * 	int code;
 * 	int val;
 * };
 *
 * struct code2frac {
 * 	int code;
 * 	float val;
 * };
 *
 * struct code2str {
 * 	int code;
 * 	char *val;
 * };
 *
 * type code2code(struct code2code *list, int code);
 * type code2frac(struct code2frac *list, int code);
 * type code2str(struct code2str *list, int code);
 */
#define CODE2X_DECLARATION
#include "code2x.h"
#undef CODE2X_DECLARATION

#endif

void **alloc_array2d(size_t rows, size_t cols, size_t entry_size);
void free_array2d(void **array2d);

