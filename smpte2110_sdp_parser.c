#include <stdlib.h>
#include <string.h>
#include "smpte2110_sdp_parser.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#define SMPTE_2110_ATTR_PARAM_ERR_REQUIRED (SMPTE_ERR_SAMPLING | \
		SMPTE_ERR_DEPTH | SMPTE_ERR_WIDTH | SMPTE_ERR_HEIGHT | \
		SMPTE_ERR_EXACTFRAMERATE | SMPTE_ERR_COLORIMETRY | \
		SMPTE_ERR_PM | SMPTE_ERR_TP | SMPTE_ERR_SSN)

#define IS_SMPTE_2110_ATTR_PARAM_ERR_REQUIRED(_err_) \
	(SMPTE_2110_ATTR_PARAM_ERR_REQUIRED & (1 << (_err_)) ? 1 : 0)

#define IS_SMPTE_2110_ATTR_PARAM_ERR_MAPPED(_err_, _map_) \
	(_map_ & (1 << (_err_)) ? 1 : 0)

#define FMTP_PARAMS_NUM 17

#define SMPTE_2110_FMTP_TABLE_START(_table_, _size_) \
	struct { \
		char *param; \
		enum sdp_parse_err (*parser)(char *str, \
			struct attr_params *params, uint32_t *err); \
		int is_parsed; \
	} _table_[_size_]; \
	do { \
		int i = 0;
#define SMPTE_2110_FMTP_NUM_ENTRY(_param_) \
	attribute_param_list[i].param = # _param_; \
	attribute_param_list[i].parser = sdp_attr_param_parse_## _param_; \
	attribute_param_list[i].is_parsed = 0; \
	i++

#define SMPTE_2110_FMTP_TABLE_END \
} while (0);

struct attr_params {
	enum smpte_2110_sampling sampling;
	enum smpte_2110_depth depth;
	uint16_t width;
	uint16_t height;
	struct smpte_2110_fps exactframerate;
	enum smpte_2110_colorimetry colorimetry;
	enum smpte_2110_pm pm;
	enum smpte_2110_tp tp;
	int is_ssn;
	int is_interlace;
	int is_segmented;
	enum smpte_2110_tcs tcs;
	enum smpte_2110_range range;
	uint16_t maxudp;
	struct smpte_2110_par par;
	uint32_t troff;
	int cmax;
};

static void attribute_params_set_defaults(struct attr_params *params)
{
	/* default for unsupported parameters */
	params->colorimetry = COLORIMETRY_UNSPECIFIED;
	params->is_ssn = 1;

	/* default for non-required parameters */
	params->is_interlace = 0;
	params->is_segmented = 0;
	params->tcs = TCS_SDR;
	params->range = RANGE_NARROW;
	params->maxudp = 1460;
	params->par.width = 1;
	params->par.height = 1;
}

/* attribute parsers */

static enum sdp_parse_err sdp_attr_param_parse_sampling(char *str,
		struct attr_params *params, uint32_t *err)
{
	int y;
	int cb;
	int cr;

	if (sscanf(str, "sampling=YCbCr-%i:%i:%i", &y, &cb, &cr) != 3) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (y != 4)
		goto err;

	if (cb == 4) {
		if (cr == 4)
			params->sampling = SAMPLING_YCbCr_444;
		else
			goto err;
	} else if (cb == 2) {
		if (cr == 2)
			params->sampling = SAMPLING_YCbCr_422;
		else if (cr == 0)
			params->sampling = SAMPLING_YCbCr_420;
		else
			goto err;
	} else {
		goto err;
	}

	*err |= SMPTE_ERR_SAMPLING;
	return SDP_PARSE_OK;

err:
	sdperr("supported samplings: 4:4:4, 4:2:2, 4:2:0");
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err sdp_attr_param_parse_depth(char *str,
		struct attr_params *params, uint32_t *err)
{
	int depth;
	char f;
	int ret;

	ret = sscanf(str, "depth=%i%c", &depth, &f);
	if (ret != 1 && ret != 2) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (ret == 2) {
		if (depth != 16 || f != 'f')
			goto err;

		params->depth = DEPTH_16F;
	} else if (ret == 1) {
		switch (depth) {
		case 8:
			params->depth = DEPTH_8;
			break;
		case 10:
			params->depth = DEPTH_10;
			break;
		case 12:
			params->depth = DEPTH_12;
			break;
		case 16:
			params->depth = DEPTH_16;
			break;
		default:
			goto err;
			break;
		}
	} else {
		goto err;
	}

	*err |= SMPTE_ERR_DEPTH;
	return SDP_PARSE_OK;

err:
	sdperr("supported depth: 8, 10, 12, 16, 16f");
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err sdp_attr_param_parse_width(char *str,
		struct attr_params *params, uint32_t *err)
{
	uint32_t width;

	if (sscanf(str, "width=%u", &width) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (width < 1 || 32767 < width) {
		sdperr("width is in the range of: [1, 32767]");
		return SDP_PARSE_ERROR;
	}

	params->width = width;
	*err |= SMPTE_ERR_WIDTH;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_height(char *str,
		struct attr_params *params, uint32_t *err)
{
	uint32_t height;

	if (sscanf(str, "height=%u", &height) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (height < 1 || 32767 < height) {
		sdperr("height is in the range of: [1, 32767]");
		return SDP_PARSE_ERROR;
	}

	params->height = height;
	*err |= SMPTE_ERR_HEIGHT;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_exactframerate(char *str,
		struct attr_params *params, uint32_t *err)
{
	int ret;
	int rate;

	ret = sscanf(str, "exactframerate=%i/1001", &rate);
	if (ret == 1) {
		params->exactframerate.is_integer = 0;
		goto exit;
	}

	ret = sscanf(str, "exactframerate=%i", &rate);
	if (ret == 1) {
		params->exactframerate.is_integer = 1;
		goto exit;
	}

	sdperr("parameter format: %s", str);
	return SDP_PARSE_ERROR;

exit:
	params->exactframerate.nominator = rate;
	*err |= SMPTE_ERR_EXACTFRAMERATE;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_colorimetry(char *str,
		struct attr_params *params, uint32_t *err)
{
	char colorimetry[256];

	if (sscanf(str, "colorimetry=%s", colorimetry) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (!strncmp(colorimetry, "BT601", strlen("BT601")))
		params->colorimetry = COLORIMETRY_BT601;
	else if (!strncmp(colorimetry, "BT709", strlen("BT709")))
		params->colorimetry = COLORIMETRY_BT709;
	else if (!strncmp(colorimetry, "BT2020", strlen("BT2020")))
		params->colorimetry = COLORIMETRY_BT2020;
	else if (!strncmp(colorimetry, "BT2100", strlen("BT2100")))
		params->colorimetry = COLORIMETRY_BT2100;
	else if (!strncmp(colorimetry, "ST2065_1", strlen("ST2065_1")))
		params->colorimetry = COLORIMETRY_ST2065_1;
	else if (!strncmp(colorimetry, "ST2065_3", strlen("ST2065_3")))
		params->colorimetry = COLORIMETRY_ST2065_3;
	else if (!strncmp(colorimetry, "UNSPECIFIED", strlen("UNSPECIFIED")))
		params->colorimetry = COLORIMETRY_UNSPECIFIED;
	else
		goto err;

	*err |= SMPTE_ERR_COLORIMETRY;
	return SDP_PARSE_OK;

err:
	sdperr("colorimetry can be: BT601, BT709, BT2020, BT2100, ST2065_1, "
		"ST2065_3, UNSPECIFIED");
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err sdp_attr_param_parse_pm(char *str,
		struct attr_params *params, uint32_t *err)
{
	char pm[256];

	if (sscanf(str, "PM=%s", pm) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (!strncmp(pm, "2110GPM", strlen("2110GPM")))
		params->pm = PM_2110GPM;
	else if (!strncmp(pm, "2110BPM", strlen("2110BPM")))
		params->pm = PM_2110BPM;
	else
		goto err;

	*err |= SMPTE_ERR_PM;
	return SDP_PARSE_OK;

err:
	sdperr("PM can be: 2110GPM, 2110BPM");
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err sdp_attr_param_parse_tp(char *str,
		struct attr_params *params, uint32_t *err)
{
	char tp[256];

	if (sscanf(str, "TP=%s", tp) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (!strncmp(tp, "2110TPN", strlen("2110TPN")))
		params->tp = TP_2110TPN;
	else if (!strncmp(tp, "2110TPNL", strlen("2110TPNL")))
		params->tp = TP_2110TPNL;
	else if (!strncmp(tp, "2110TPW", strlen("2110TPW")))
		params->tp = TP_2110TPW;
	else
		goto err;

	*err |= SMPTE_ERR_TP;
	return SDP_PARSE_OK;

err:
	sdperr("TP can be: 2110TPN, 2110TPNL, 2110TPW");
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err sdp_attr_param_parse_ssn(char *str,
		struct attr_params *params, uint32_t *err)
{
	if (strncmp(str, "SSN=ST2110-20:2017", strlen("SSN=ST2110-20:2017")) &&
			strncmp(str, "SSN=\"ST2110-20:2017\"",
			strlen("SSN=\"ST2110-20:2017\""))) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	params->is_ssn = 1;
	*err |= SMPTE_ERR_SSN;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_interlace(char *str,
		struct attr_params *params, uint32_t *err)
{
	if (strncmp(str, "interlace", strlen("interlace"))) {
		sdperr("parameter format: interlace");
		return SDP_PARSE_ERROR;
	}

	params->is_interlace = 1;
	*err |= SMPTE_ERR_INERLACE;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_segmented(char *str,
		struct attr_params *params, uint32_t *err)
{
	if (strncmp(str, "segmented", strlen("segmented"))) {
		sdperr("parameter format: segmented");
		return SDP_PARSE_ERROR;
	}

	params->is_segmented = 1;
	*err |= SMPTE_ERR_SEGMENTED;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_tcs(char *str,
		struct attr_params *params, uint32_t *err)
{
	char tcs[256];

	if (sscanf(str, "TCS=%s", tcs) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (!strncmp(tcs, "SDR", strlen("SDR")))
		params->tcs = TCS_SDR;
	else if (!strncmp(tcs, "PQ", strlen("PQ")))
		params->tcs = TCS_PQ;
	else if (!strncmp(tcs, "HLG", strlen("HLGS")))
		params->tcs = TCS_HLG;
	else if (!strncmp(tcs, "LINEAR", strlen("LINEAR")))
		params->tcs = TCS_LINEAR;
	else if (!strncmp(tcs, "BT2100LINPQ", strlen("BT2100LINPQ")))
		params->tcs = TCS_BT2100LINPQ;
	else if (!strncmp(tcs, "BT2100LINHLG", strlen("BT2100LINHLG")))
		params->tcs = TCS_BT2100LINHLG;
	else if (!strncmp(tcs, "ST2065-1", strlen("ST2065-1")))
		params->tcs = TCS_ST2065_1;
	else if (!strncmp(tcs, "ST428-1", strlen("ST428-1")))
		params->tcs = TCS_ST428_1;
	else if (!strncmp(tcs, "DENSITY", strlen("DENSITY")))
		params->tcs = TCS_DENSITY;
	else if (!strncmp(tcs, "UNSPECIFIED", strlen("UNSPECIFIED")))
		params->tcs = TCS_UNSPECIFIED;
	else
		goto err;

	*err |= SMPTE_ERR_TCS;
	return SDP_PARSE_OK;

err:
	sdperr("TCS can be: SDR, PQ, HLG, LINEAR, BT2100LINPQ, BT2100LINHLG, "
		"ST2065-1, ST428-1, DENSITY, UNSPECIFIED");
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err sdp_attr_param_parse_range(char *str,
		struct attr_params *params, uint32_t *err)
{
	char range[256];

	if (sscanf(str, "RANGE=%s", range) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (!strncmp(range, "NARROW", strlen("NARROW")))
		params->range = RANGE_NARROW;
	else if (!strncmp(range, "FULL", strlen("FULL")))
		params->range = RANGE_FULL;
	else if (!strncmp(range, "FULLPROTECT", strlen("FULLPROTECT")))
		params->range = RANGE_FULLPROTECT;
	else
		goto err;

	*err |= SMPTE_ERR_RANGE;
	return SDP_PARSE_OK;

err:
	sdperr("RANGE can be: NARROW, FULL, FULLPROTECT");
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err sdp_attr_param_parse_maxudp(char *str,
		struct attr_params *params, uint32_t *err)
{
	uint32_t maxudp;

	if (sscanf(str, "MAXUDP=%u", &maxudp) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	if (maxudp != 1460 && maxudp != 8960)
		goto err;

	params->maxudp = maxudp;
	*err |= SMPTE_ERR_MAXUDP;
	return SDP_PARSE_OK;

err:
	sdperr("MAXUDP can be: 1460, 8960");
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err sdp_attr_param_parse_par(char *str,
		struct attr_params *params, uint32_t *err)
{
	uint32_t width;
	uint32_t height;

	if (sscanf(str, "PAR=%u:%u", &width, &height) != 2) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	params->par.width = width;
	params->par.height = height;
	*err |= SMPTE_ERR_PAR;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_troff(char *str,
		struct attr_params *params, uint32_t *err)
{
	uint32_t troff;

	if (sscanf(str, "TROFF=%u", &troff) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	params->troff = troff;
	*err |= SMPTE_ERR_TROFF;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_cmax(char *str,
		struct attr_params *params, uint32_t *err)
{
	int cmax;

	if (sscanf(str, "CMAX=%i", &cmax) != 1) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	params->cmax = cmax;
	*err |= SMPTE_ERR_CMAX;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err smpte2110_sdp_parse_fmtp_params(
		struct sdp_media *media,struct sdp_attr *a, char *value,
		char *params)
{
	struct attr_params p;
	char *token;
	char *endptr;
	struct smpte2110_media_attr_fmtp *smpte2110_fmtp;
	size_t i;
	int fmt;
	struct sdp_attr *rtpmap_attr;
	SMPTE_2110_FMTP_TABLE_START(attribute_param_list, FMTP_PARAMS_NUM)
		SMPTE_2110_FMTP_NUM_ENTRY(sampling);
		SMPTE_2110_FMTP_NUM_ENTRY(depth);
		SMPTE_2110_FMTP_NUM_ENTRY(width);
		SMPTE_2110_FMTP_NUM_ENTRY(height);
		SMPTE_2110_FMTP_NUM_ENTRY(exactframerate);
		SMPTE_2110_FMTP_NUM_ENTRY(colorimetry);
		SMPTE_2110_FMTP_NUM_ENTRY(pm);
		SMPTE_2110_FMTP_NUM_ENTRY(tp);
		SMPTE_2110_FMTP_NUM_ENTRY(ssn);
		SMPTE_2110_FMTP_NUM_ENTRY(interlace);
		SMPTE_2110_FMTP_NUM_ENTRY(segmented);
		SMPTE_2110_FMTP_NUM_ENTRY(tcs);
		SMPTE_2110_FMTP_NUM_ENTRY(range);
		SMPTE_2110_FMTP_NUM_ENTRY(maxudp);
		SMPTE_2110_FMTP_NUM_ENTRY(par);
		SMPTE_2110_FMTP_NUM_ENTRY(troff);
		SMPTE_2110_FMTP_NUM_ENTRY(cmax);
	SMPTE_2110_FMTP_TABLE_END

	/* identify if this a=fmtp descirbes raw video or not */
	fmt = strtol(value, &endptr, 10);
	if (*endptr) {
		sdperr("bad fmt - %s", value);
		return SDP_PARSE_ERROR;
	}
	/* Assumption: a=rtpmap comes before a=fmtp in the media block */
	for (rtpmap_attr = sdp_media_attr_get(media, SDP_ATTR_RTPMAP);
			rtpmap_attr;
			rtpmap_attr = sdp_attr_get_next(rtpmap_attr )) {
		if (strncmp(rtpmap_attr->value.rtpmap.media_subtype, "raw", 3))
			continue;

		if (rtpmap_attr->value.rtpmap.fmt == fmt)
			break;
		
		sdperr("fmtp wrong format - %d (expected - %d)", fmt,
			rtpmap_attr->value.rtpmap.fmt);
		return SDP_PARSE_ERROR;
	}

	if (!rtpmap_attr)
		return SDP_PARSE_NOT_SUPPORTED;

	smpte2110_fmtp = (struct smpte2110_media_attr_fmtp *)calloc(1,
		sizeof(struct smpte2110_media_attr_fmtp));
	if (!smpte2110_fmtp) {
		sdperr("Memory allocation");
		goto fail;
	}

	attribute_params_set_defaults(&p);

	smpte2110_fmtp->err = 0; /* no attribute params have been parsed */
	while ((token = strtok(params, ";"))) {
		/* skip the white space(s) peceding the current token */
		while (IS_WHITESPACE(*token))
			token++;

		if (!*token)
			break;

		for (i = 0; i < ARRAY_SIZE(attribute_param_list) &&
			strncasecmp(token, attribute_param_list[i].param,
				strlen(attribute_param_list[i].param)); i++);

		/* verify attribute is found in list */
		if (i == ARRAY_SIZE(attribute_param_list)) {
			sdperr("unknown attribute: %s", token);
			goto fail;
		}

		/* verify no multiple attribute signalling */
		if (attribute_param_list[i].is_parsed) {
			sdperr("multiple attribute signalling: %s",
				attribute_param_list[i].param);
			goto fail;
		}

		/* parse attribute */
		if (attribute_param_list[i].parser(token, &p,
				&smpte2110_fmtp->err) == SDP_PARSE_ERROR) {
			goto fail;
		}

		/* mark attriute as parsed */
		attribute_param_list[i].is_parsed = 1;
		params = NULL;
	}

	/* assert all required attriute parameters have been provided */
	for (i = 0; i < ARRAY_SIZE(attribute_param_list); i++) {
		if ((IS_SMPTE_2110_ATTR_PARAM_ERR_REQUIRED(i)) &&
			!IS_SMPTE_2110_ATTR_PARAM_ERR_MAPPED(i,
				smpte2110_fmtp->err)) {
			sdperr("missing required fmtp parameter: %s",
				attribute_param_list[i].param);
			goto fail;
		}
	}

	/* assert segmented parameter is not provided without interlace */
	if (p.is_segmented && ! p.is_interlace) {
		sdperr("cannot signal 'segmented' without 'interlace'");
		goto fail;
	}

	/* update output paprameters */
	smpte2110_fmtp->params.sampling = p.sampling;
	smpte2110_fmtp->params.depth = p.depth;
	smpte2110_fmtp->params.width = p.width;
	smpte2110_fmtp->params.height = p.height;
	smpte2110_fmtp->params.exactframerate = p.exactframerate;
	smpte2110_fmtp->params.colorimetry = p.colorimetry;
	smpte2110_fmtp->params.pm = p.pm;
	smpte2110_fmtp->params.signal = p.is_interlace ?
		p.is_segmented ? SIGNAL_PSF : SIGNAL_INTERLACE :
			SIGNAL_PROGRESSIVE;
	smpte2110_fmtp->params.tcs = p.tcs;
	smpte2110_fmtp->params.range = p.range;
	smpte2110_fmtp->params.maxudp = p.maxudp;
	smpte2110_fmtp->params.par = p.par;

	a->type = SDP_ATTR_FMTP;
	a->value.fmtp.params = smpte2110_fmtp;
	a->value.fmtp.param_dtor = free;

	return SDP_PARSE_OK;

fail:
	free(smpte2110_fmtp);
	return SDP_PARSE_ERROR;
}

static enum sdp_parse_err smpte2110_sdp_parse_group(struct sdp_attr *a,
		char *value, char *params)
{
	char *tmp;
	struct group_identification_tag **tag;
	struct sdp_attr_value_group *group = &a->value.group;

	if (strncmp(value, "DUP", strlen("DUP"))) {
		sdperr("unsupported group semantic for media: %s", value);
		return SDP_PARSE_ERROR;
	}

	if (!params) {
		sdperr("group DUP attriute bad format - no params");
		return SDP_PARSE_ERROR;
	}

	if (!(group->semantic = strdup(value))) {
		sdperr("memory allocation");
		goto fail;
	}

	tag = &group->tag;
	do {
		char *cur = strtok_r(params, " ", &tmp);

		*tag = (struct group_identification_tag*)calloc(1,
			sizeof(struct group_identification_tag));
		if (!*tag || !((*tag)->identification_tag = strdup(cur))) {
			sdperr("memory allocation");
			goto fail;
		}

		group->num_tags++;
		tag = &(*tag)->next;
		params = NULL;
	} while (*tmp);

	a->type = SDP_ATTR_GROUP;
	return SDP_PARSE_OK;

fail:
	tag = &group->tag;
	while (*tag) {
		struct group_identification_tag *tmp = *tag;

		tag = &(*tag)->next;
		free(tmp->identification_tag);
		free(tmp);
	}

	return SDP_PARSE_ERROR;
}

enum sdp_parse_err smpte2110_sdp_parse_specific(struct sdp_media *media,
		struct sdp_attr *a, char *attr, char *value, char *params)
{
	if (media && media->m.type != SDP_MEDIA_TYPE_VIDEO)
		return SDP_PARSE_OK;

	if (!strncmp(attr, "fmtp", strlen("fmtp")))
		return smpte2110_sdp_parse_fmtp_params(media, a, value, params);

	if (!strncmp(attr, "group", strlen("group")))
		return smpte2110_sdp_parse_group(a, value, params);

	return SDP_PARSE_ERROR;
}

