#include <stdlib.h>

#undef CODE2X

#ifdef CODE2X_DECLARATION
#define CODE2X(type, name, def) \
struct code2##name { \
	int code; \
	type val; \
}; \
type code2##name(struct code2##name *list, int code);
#else
#ifdef CODE2X_IMPLEMENTATION
#define CODE2X(type, name, def) type code2##name(struct code2##name *list, \
		int code) \
{ \
	for ( ; list->code != -1 && list->code != code; list++); \
	return list->code != -1 || list->val ? list->val : def; \
}
#else
#define CODE2X(type, name, def)
#endif
#endif

CODE2X(int, code, -1)
CODE2X(float, frac, -1.0)
CODE2X(char *, str, NULL)

