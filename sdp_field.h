#ifndef _SDP_FIELD_H_
#define _SDP_FIELD_H_

#include <stdlib.h>

#include "sdp_parser.h"

#ifndef NOT_IN_USE
#define NOT_IN_USE(a) ((void)(a))
#endif

/* Parse help function: */
enum sdp_parse_err sdp_parse_str(char **result, const char *input);
enum sdp_parse_err sdp_parse_int(int *result, const char *input);
enum sdp_parse_err sdp_parse_long(long *result, const char *input);
enum sdp_parse_err sdp_parse_long_long(long long *result, const char *input);
enum sdp_parse_err sdp_parse_float(float *result, const char *input);
enum sdp_parse_err sdp_parse_double(double *result, const char *input);

const char *get_attr_type_name(enum sdp_attr_type type);
int sdp_validate_sub_types(struct sdp_media *media);
int sdp_validate_required_attributes(struct sdp_media* media,
		int (*get_required_attr_mask)(int sub_type));

/* Field parse/free wrappers: */
enum sdp_parse_err sdp_parse_field_default(struct interpretable *field,
		char *input);
enum sdp_parse_err sdp_parse_field(struct sdp_media *media,
		struct sdp_attr *attr, struct interpretable *field, char *input,
		sdp_field_interpreter specific_field_interpreter);
void sdp_free_field(struct interpretable *field);

#endif /* _SDP_FIELD_H_ */
