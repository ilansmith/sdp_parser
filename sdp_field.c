#include <string.h>
#include "sdp_parser.h"
#include "sdp_field.h"

static enum sdp_parse_err sdp_parse_type_verify(char *endptr,
		const char *input, const char *expected_name)
{
	if (*endptr) {
		sdperr("invalid value '%s'. %s is expected", input,
				expected_name);
		return SDP_PARSE_ERROR;
	}
	return SDP_PARSE_OK;
}

enum sdp_parse_err sdp_parse_str(char **result, const char *input)
{
	if (!input)
		return sdprerr("no value specified");
	*result = strdup(input);
	return (*result) ?
		SDP_PARSE_OK :
		sdprerr("memory allocation failed");
}

enum sdp_parse_err sdp_parse_int(int *result, const char *input)
{
	char *endptr;

	if (!input)
		return sdprerr("no value specified");
	*result = strtol(input, &endptr, 10);
	return sdp_parse_type_verify(endptr, input, "Integer");
}

enum sdp_parse_err sdp_parse_long(long *result, const char *input)
{
	char *endptr;

	if (!input)
		return sdprerr("no value specified");
	*result = strtol(input, &endptr, 10);
	return sdp_parse_type_verify(endptr, input, "Integer");
}

enum sdp_parse_err sdp_parse_long_long(long long *result, const char *input)
{
	char *endptr;

	if (!input)
		return sdprerr("no value specified");
	*result = strtoll(input, &endptr, 10);
	return sdp_parse_type_verify(endptr, input, "Integer");
}

enum sdp_parse_err sdp_parse_float(float *result, const char *input)
{
	char *endptr;

	if (!input)
		return sdprerr("no value specified");
	*result = strtof(input, &endptr);
	return sdp_parse_type_verify(endptr, input, "Number");
}

enum sdp_parse_err sdp_parse_double(double *result, const char *input)
{
	char *endptr;

	if (!input)
		return sdprerr("no value specified");
	*result = strtod(input, &endptr);
	return sdp_parse_type_verify(endptr, input, "Number");
}


static int attr_is_of_format(struct sdp_attr *attr, int fmt_id)
{
	if (attr->type == SDP_ATTR_FMTP)
		return attr->value.fmtp.fmt->id == fmt_id;
	if (attr->type == SDP_ATTR_RTPMAP)
		return attr->value.rtpmap.fmt->id == fmt_id;
	return 1;
}

static int validate_fmt_required_attributes(struct sdp_media* media,
		struct sdp_media_fmt *fmt, int required_attr_mask)
{
	struct sdp_attr *attr;

	for (attr = media->a; attr; attr = attr->next) {
		if (attr_is_of_format(attr, fmt->id))
			required_attr_mask &= ~(1 << attr->type);
	}

	if (required_attr_mask != 0) {
		enum sdp_attr_type attr = 0;

		sdperr("media format %u is missing required attributes:",
				fmt->id);
		while (required_attr_mask > 0) {
			if (required_attr_mask & 0x1)
				sdperr("   (%02u) %s", attr,
						sdp_get_attr_type_name(attr));
			required_attr_mask >>= 1;
			attr += 1;
		}
		return 0;
	}
	return 1;
}

int sdp_validate_required_attributes(struct sdp_media *media,
		int (*get_required_attr_mask)(int sub_type))
{
	struct sdp_media_fmt *fmt;
	int attr_mask = 0;

	for (fmt = &media->m.fmt; fmt; fmt = fmt->next) {
		attr_mask = get_required_attr_mask(fmt->sub_type);
		if (!validate_fmt_required_attributes(media, fmt, attr_mask))
			return 0;
	}
	return 1;
}

int sdp_validate_sub_types(struct sdp_media *media)
{
	struct sdp_media_fmt *fmt;

	for (fmt = &media->m.fmt; fmt; fmt = fmt->next) {
		if (fmt->sub_type == SDP_SUB_TYPE_UNKNOWN) {
			sdperr("no valid sub type recognized for format %u",
					fmt->id);
			return 0;
		}
	}
	return 1;
}

enum sdp_parse_err sdp_parse_field_default(struct interpretable *field,
		char *input)
{
	if (!input) {
		field->as.as_str = "";
		return SDP_PARSE_OK;
 	}
	if (sdp_parse_str(&field->as.as_str, input) != SDP_PARSE_OK)
		return SDP_PARSE_ERROR;
	field->dtor = free;
	return SDP_PARSE_OK;
}

enum sdp_parse_err sdp_parse_field(struct sdp_media *media,
		struct sdp_attr *attr, struct interpretable *field, char *input,
		sdp_field_interpreter specific_field_interpreter)
{
	/*
	 * If a specific interpreter is used, pass the input as is.
	 * Allow specific default value for NULL input (optional field).
	 */
	if (specific_field_interpreter)
		return specific_field_interpreter(media, attr, field, input);
	return sdp_parse_field_default(field, input);
}

void sdp_free_field(struct interpretable *field)
{
	if (field->dtor)
		field->dtor(field->as.as_ptr);
}
