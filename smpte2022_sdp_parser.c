#include <string.h>

#include "sdp_parser.h"
#include "sdp_field.h"
#include "smpte2022_sdp_parser.h"

static int get_required_attr_mask(int sub_type)
{
	switch (sub_type) {
	case SMPTE_2022_SUB_TYPE_6:
		return 0;
	default:
		return 0;
	}
}

static enum sdp_parse_err smpte2022_parse_rtpmap_encoding_name(
		struct sdp_media *media, struct sdp_attr *attr,
		struct interpretable *field, char *input)
{
	int *sub_type = &attr->value.rtpmap.fmt->sub_type;

	if (media->m.type == SDP_MEDIA_TYPE_VIDEO) {
		if (!strcmp(input, "smpte2022-6"))
			*sub_type = SMPTE_2022_SUB_TYPE_6;
	}
	return sdp_parse_field_default(field, input);
}

static enum sdp_parse_err smpte2022_validate_media(struct sdp_media *media)
{

	if (!sdp_validate_sub_types(media))
		return SDP_PARSE_NOT_SUPPORTED;
	if (!sdp_validate_required_attributes(media, get_required_attr_mask))
		return SDP_PARSE_ERROR;
	return SDP_PARSE_OK;
}

static struct sdp_specific smpte2022_specific =
{
	"smpte2022",
	NULL,
	NULL,
	smpte2022_parse_rtpmap_encoding_name,
	NULL,
	smpte2022_validate_media,
};

struct sdp_specific *smpte2022 = &smpte2022_specific;
