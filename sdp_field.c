#include <string.h>
#include "sdp_parser.h"
#include "sdp_field.h"

static struct sdp_specific empty_specific = SDP_SPECIFIC_INIT;

struct sdp_specific *no_specific = &empty_specific;

enum sdp_parse_err sdp_parse_type_verify(char *endptr, const char *input,
	const char *expected_name)
{
	if (*endptr) {
		sdperr("invalid value '%s'. %s is expected.", input, expected_name);
		return SDP_PARSE_ERROR;
	}
	return SDP_PARSE_OK;
}

enum sdp_parse_err sdp_parse_str(char **result, const char *input)
{
	if (!input)
		return sdprerr("no value specified.");
	*result = strdup(input);
	return (*result) ?
		SDP_PARSE_OK :
		sdprerr("memory allocation failed.");
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

enum sdp_parse_err sdp_parse_field_default(struct interpretable *field,
		char *input)
{
	if (!input) {
 		field->as.as_ptr = NULL;
		return SDP_PARSE_OK;
 	}
	field->dtor = free;
	return sdp_parse_str(&field->as.as_str, input);
}

enum sdp_parse_err sdp_parse_field(struct sdp_media *media,
		struct sdp_attr *attr, struct interpretable *field, char *input,
		sdp_field_interpreter specific_field_interpreter)
{
	/*
	 * If a specific interpreter is used, pass the input as is.
	 * Allow specific default value for NULL input (optional field).
	 */
	field->dtor = NULL;
	if (specific_field_interpreter)
		return specific_field_interpreter(media, attr, field, input);
	return sdp_parse_field_default(field, input);
}

void sdp_free_field(struct interpretable *field)
{
	if (field->dtor)
		field->dtor(field->as.as_ptr);
}
