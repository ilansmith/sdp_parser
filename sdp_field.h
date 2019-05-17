#ifndef _SDP_FIELD_H_
#define _SDP_FIELD_H_

#include <stdlib.h>

enum sdp_parse_err {
	SDP_PARSE_OK,
	SDP_PARSE_NOT_SUPPORTED,
	SDP_PARSE_ERROR,
};

struct sdp_attr;
struct sdp_media;
struct sdp_media_m;

typedef struct {
	union {
		long long as_ll;
		double as_d;
		void *as_ptr;
		char *as_str;
	} as;
	void (*dtor)(void *params);
} interpretable;

typedef enum sdp_parse_err (*sdp_field_interpreter)(interpretable *field, const char *input);
typedef enum sdp_parse_err (*sdp_attribute_interpreter)(struct sdp_media* media, struct sdp_attr *attr, char* value, char* params);
typedef enum sdp_parse_err (*sdp_media_validator)(struct sdp_media* media);

/* Session level interpreter */
struct sdp_session_interpreter {
	sdp_attribute_interpreter group;
};

/* Media level interpreter */
struct sdp_media_interpreter {
	sdp_attribute_interpreter fmtp;
	sdp_field_interpreter fmtp_params;
	sdp_field_interpreter rtpmap_encoding_name;
	sdp_field_interpreter rtpmap_encoding_parameters;
	sdp_media_validator validator;
};

struct sdp_specific {
	struct sdp_session_interpreter* (*get_session_interpreter)();
	struct sdp_media_interpreter* (*get_media_interpreter)(struct sdp_media_m* media_m);
};

#define SDP_SESSION_INTERPRETER_INIT() { NULL }
#define SDP_MEDIA_INTERPRETER_INIT() { NULL, NULL, NULL, NULL, NULL }

/* Empty/default interpreters: */
struct sdp_session_interpreter *no_specific_session_interpreter();
struct sdp_media_interpreter *no_specific_media_interpreter(struct sdp_media_m* media_m);
void no_free_required(interpretable *field);
extern struct sdp_specific *no_specific;

/* Parse help function: */
enum sdp_parse_err sdp_parse_int(int *result, const char *input);
enum sdp_parse_err sdp_parse_long(long *result, const char *input);
enum sdp_parse_err sdp_parse_long_long(long long *result, const char *input);
enum sdp_parse_err sdp_parse_float(float *result, const char *input);
enum sdp_parse_err sdp_parse_double(double *result, const char *input);

/* Field parse/free wrappers: */
enum sdp_parse_err sdp_parse_field(interpretable *field, const char *input,
		sdp_field_interpreter specific_field_interpreter);
void sdp_free_field(interpretable *field);

#endif /* _SDP_FIELD_H_ */
