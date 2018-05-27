#include <string.h>
#include "sdp_parser.h"
#include "sdp_field.h"

static struct sdp_session_interpreter empty_session_interpreter = SDP_SESSION_INTERPRETER_INIT();
static struct sdp_media_interpreter empty_media_interpreter = SDP_MEDIA_INTERPRETER_INIT();

struct sdp_session_interpreter *no_specific_session_interpreter()
{
	return &empty_session_interpreter;
}

struct sdp_media_interpreter *no_specific_media_interpreter(struct sdp_media_m* media_m)
{
	(void)media_m;
	return &empty_media_interpreter;
}

static struct sdp_specific empty_specific =
{
	no_specific_session_interpreter,
	no_specific_media_interpreter
};

struct sdp_specific *no_specific = &empty_specific;

void no_free_required(interpretable* field)
{
	(void)field;
}

enum sdp_parse_err sdp_parse_type_verify(char *endptr, const char *input,
	const char* expected_name)
{
	if (*endptr) {
		sdperr("invalid value '%s'. %s is expected.", input, expected_name);
		return SDP_PARSE_ERROR;
	}
	return SDP_PARSE_OK;
}

enum sdp_parse_err sdp_parse_int(int *result, const char *input)
{
	char *endptr;
	if (!input)
		return sdprerr("no value specified.");
	*result = strtol(input, &endptr, 10);
	return sdp_parse_type_verify(endptr, input, "Integer");
}

enum sdp_parse_err sdp_parse_long(long *result, const char *input)
{
	char *endptr;
	if (!input)
		return sdprerr("no value specified.");
	*result = strtol(input, &endptr, 10);
	return sdp_parse_type_verify(endptr, input, "Integer");
}

enum sdp_parse_err sdp_parse_long_long(long long *result, const char *input)
{
	char *endptr;
	if (!input)
		return sdprerr("no value specified.");
	*result = strtoll(input, &endptr, 10);
	return sdp_parse_type_verify(endptr, input, "Integer");
}

enum sdp_parse_err sdp_parse_float(float *result, const char *input)
{
	char *endptr;
	if (!input)
		return sdprerr("no value specified.");
	*result = strtof(input, &endptr);
	return sdp_parse_type_verify(endptr, input, "Number");
}

enum sdp_parse_err sdp_parse_double(double *result, const char *input)
{
	char *endptr;
	if (!input)
		return sdprerr("no value specified.");
	*result = strtod(input, &endptr);
	return sdp_parse_type_verify(endptr, input, "Number");
}

enum sdp_parse_err sdp_parse_field(interpretable *field, const char *input,
		sdp_field_interpreter specific_field_interpreter)
{
	/* If a specific interpreter is used, pass the input as is. Allow specific
	 * default value for NULL input (optional field).*/
	field->dtor = NULL;
	if (specific_field_interpreter) {
		return specific_field_interpreter(field, input);
	}
	if (input) {
		field->as.as_str = strdup(input);
		field->dtor = free;
	} else {
		field->as.as_ptr = NULL;
	}
	return SDP_PARSE_OK;
}

void sdp_free_field(interpretable* field)
{
	if (field->dtor)
		field->dtor(field->as.as_ptr);
}
