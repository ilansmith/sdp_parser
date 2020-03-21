#include "sdp_compat.h"

ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
	char *bufptr;
	char *p;
	size_t size;
	int c;

	if (!lineptr || !n || !stream)
		return -1;

	if (!*lineptr) {
		bufptr = (char*)malloc(INCREASE_BLOCK);
		if (!bufptr)
		return -1;
		size = INCREASE_BLOCK;
	} else {
	bufptr = *lineptr;
	size = *n;
	}

	p = bufptr;
	while ((c = fgetc(stream) != EOF)) {
		if ((p - bufptr) > (int)(size - sizeof('\0'))) {
			char *new_bufptr;

			size += INCREASE_BLOCK;
			new_bufptr = (char*)realloc(bufptr, size);
			if (!new_bufptr)
				return -1;

			p = new_bufptr + (p - bufptr);
			bufptr = new_bufptr;
			}
		*p++ = (char)c;
		if (c == '\n')
			break;
		c = fgetc(stream);
	}
	if (p == bufptr)
		return -1;

	*p++ = '\0';
	*lineptr = bufptr;
	*n = size;

	return p - bufptr - 1;
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
	if (!n)
		return 0;

	while (tolower(*s1) == tolower(*s2)) {
		if (!--n || !*s1 || !*s2)
			break;
		s1++;
		s2++;
	}

	return tolower(*(unsigned char*)s1) - tolower(*(unsigned char*)s2);
}

