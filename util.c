#include <stdlib.h>
#include <stdint.h>
#include "util.h"

#define CODE2X_IMPLEMENTATION
#include "code2x.h"
#undef CODE2X_IMPLEMENTATION

/*
 * Example
 *   **array2d points to an array of 4x2. That is, an array of 4 rows and
 *   2 columns. Each entry in this example is of size 2:
 *
 *                                                   rows
 *                                                   |
 *                                                   V
 *                                                  ______________________
 *                                                 /                      \
 *                                                   entry_size * cols
 *                                                   |
 *                                                   |    entry_size
 *              rows                                 V    |
 *              |                                   ___   |__   ___   ___
 *              V                                  /   \ /|  \ /   \ /   \
 *             __________________________________         V
 *            /                                  \ /\ /\ /\ /\ /\ /\ /\ /\
 *            +--------+--------+--------+--------+-----+-----+-----+-----+
 * array2d -> |uint8_t*|uint8_t*|uint8_t*|uint8_t*|e |e |e |e |e |e |e |e |
 *            +--------+--------+--------+--------+-----+-----+-----+-----+
 *               |        |        |        |     ^     ^     ^     ^
 *               |        |        |        |     |     |     |     |
 *               \________________________________/     |     |     |
 *                        |        |        |           |     |     |
 *                        \_____________________________/     |     |
 *                                 |        |                 |     |
 *                                 \__________________________/     |
 *                                          |                       |
 *                                          \_______________________/
 *
 */
void **alloc_array2d(size_t rows, size_t cols, size_t entry_size)
{
	uint8_t *array2d;
	size_t array2d_len = (sizeof(uint8_t*) + entry_size * cols) * rows;
	size_t i;

	array2d = (uint8_t*)calloc(array2d_len, 1);
	if (!array2d)
		return NULL;

	for (i = 0; i < rows; i++) {
		((uint8_t**)array2d)[i] = array2d + sizeof(uint8_t*) * rows +
			entry_size * cols * i;
	}

	return (void**)array2d;
}

void free_array2d(void **array2d)
{
	free(array2d);
}

