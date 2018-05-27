#ifndef _SDP_FIELD_H_
#define _SDP_FIELD_H_

#include <stdlib.h>

#ifndef NOT_IN_USE
#define NOT_IN_USE(a) ((void)(a))
#endif

#define SDP_SPECIFIC_INIT { NULL, NULL, NULL, NULL, NULL }

struct sdp_attr;
struct sdp_media;
struct sdp_media_m;

enum sdp_parse_err {
	SDP_PARSE_OK,
	SDP_PARSE_NOT_SUPPORTED,
	SDP_PARSE_ERROR,
};

struct interpretable{
	union {
		long long as_ll;
		double as_d;
		void *as_ptr;
		char *as_str;
	} as;
	void (*dtor)(void *params);
};

typedef enum sdp_parse_err (*sdp_field_interpreter)(
		struct sdp_media *media, struct sdp_attr *attr,
		struct interpretable *field, char *input);
typedef enum sdp_parse_err (*sdp_attribute_interpreter)(
		struct sdp_media *media, struct sdp_attr *attr, char *value,
		char *params);
typedef enum sdp_parse_err (*sdp_media_validator)(struct sdp_media *media);

/* Media level interpreter */
struct sdp_specific {
	sdp_attribute_interpreter group;
	sdp_field_interpreter fmtp_params;
	sdp_field_interpreter rtpmap_encoding_name;
	sdp_field_interpreter rtpmap_encoding_parameters;
	sdp_media_validator validator;
};

/* Empty/default interpreters: */
struct sdp_session_interpreter *no_specific_session_interpreter(void);
struct sdp_media_interpreter *no_specific_media_interpreter(
		struct sdp_media_m *media_m);
extern struct sdp_specific *no_specific;

/* Parse help function: */
enum sdp_parse_err sdp_parse_str(char **result, const char *input);
enum sdp_parse_err sdp_parse_int(int *result, const char *input);
enum sdp_parse_err sdp_parse_long(long *result, const char *input);
enum sdp_parse_err sdp_parse_long_long(long long *result, const char *input);
enum sdp_parse_err sdp_parse_float(float *result, const char *input);
enum sdp_parse_err sdp_parse_double(double *result, const char *input);

/* Field parse/free wrappers: */
enum sdp_parse_err sdp_parse_field_default(struct interpretable *field,
		char *input);
enum sdp_parse_err sdp_parse_field(struct sdp_media *media,
		struct sdp_attr *attr, struct interpretable *field, char *input,
		sdp_field_interpreter specific_field_interpreter);
void sdp_free_field(struct interpretable *field);

#endif /* _SDP_FIELD_H_ */
