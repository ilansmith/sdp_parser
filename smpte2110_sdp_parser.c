#include <stdlib.h>
#include <string.h>

#include "safestringlib/safe_str_lib.h"
#include "smpte2110_sdp_parser.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#define SMPTE_2110_ATTR_PARAM_ERR_REQUIRED (SMPTE_ERR_SAMPLING | \
		SMPTE_ERR_DEPTH | SMPTE_ERR_WIDTH | SMPTE_ERR_HEIGHT | \
		SMPTE_ERR_EXACTFRAMERATE | SMPTE_ERR_COLORIMETRY | \
		SMPTE_ERR_PM | SMPTE_ERR_TP | SMPTE_ERR_SSN)

#define SMPTE_2110_ATTR_PARAM_REQUIRED(_err_) \
	(((_err_) & SMPTE_2110_ATTR_PARAM_ERR_REQUIRED) == \
	 SMPTE_2110_ATTR_PARAM_ERR_REQUIRED)

#define SDP_ATTR_PARAM_PARSE(_param_) \
	{ \
		.param = # _param_, \
		.parser = sdp_attr_param_parse_ ## _param_, \
		.is_parsed = 0 \
	}

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
};

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

	if (sscanf(str, "width=%i", &width) != 1) {
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

	if (sscanf(str, "height=%i", &height) != 1) {
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

	if (!strncmp(colorimetry, "BT601", 5))
		params->colorimetry = COLORIMETRY_BT601;
	else if (!strncmp(colorimetry, "BT709", 5))
		params->colorimetry = COLORIMETRY_BT709;
	else if (!strncmp(colorimetry, "BT2020", 6))
		params->colorimetry = COLORIMETRY_BT2020;
	else if (!strncmp(colorimetry, "BT2100", 6))
		params->colorimetry = COLORIMETRY_BT2100;
	else if (!strncmp(colorimetry, "ST2065_1", 8))
		params->colorimetry = COLORIMETRY_ST2065_1;
	else if (!strncmp(colorimetry, "ST2065_3", 8))
		params->colorimetry = COLORIMETRY_ST2065_3;
	else if (!strncmp(colorimetry, "UNSPECIFIED", 11))
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

	if (!strncmp(pm, "2110GPM", 7))
		params->pm = PM_2110GPM;
	else if (!strncmp(pm, "2110BPM", 7))
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

	if (!strncmp(tp, "2110TPN", 7))
		params->tp = TP_2110TPN;
	else if (!strncmp(tp, "2110TPNL", 8))
		params->tp = TP_2110TPNL;
	else if (!strncmp(tp, "2110TPW", 7))
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
	if (strncmp(str, "SSN=ST2110-20:2017", 18) &&
			strncmp(str, "\"SSN=ST2110-20:2017\"", 20)) {
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
	if (strncmp(str, "interlace", 9)) {
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
	if (strncmp(str, "segmented", 9)) {
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

	if (!strncmp(tcs, "SDR", 3))
		params->tcs = TCS_SDR;
	else if (!strncmp(tcs, "PQ", 2))
		params->tcs = TCS_PQ;
	else if (!strncmp(tcs, "HLG", 4))
		params->tcs = TCS_HLG;
	else if (!strncmp(tcs, "LINEAR", 6))
		params->tcs = TCS_LINEAR;
	else if (!strncmp(tcs, "BT2100LINPQ", 11))
		params->tcs = TCS_BT2100LINPQ;
	else if (!strncmp(tcs, "BT2100LINHLG", 12))
		params->tcs = TCS_BT2100LINHLG;
	else if (!strncmp(tcs, "ST2065-1", 8))
		params->tcs = TCS_ST2065_1;
	else if (!strncmp(tcs, "ST428-1", 7))
		params->tcs = TCS_ST428_1;
	else if (!strncmp(tcs, "DENSITY", 7))
		params->tcs = TCS_DENSITY;
	else if (!strncmp(tcs, "UNSPECIFIED", 11))
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

	if (!strncmp(range, "NARROW", 6))
		params->range = RANGE_NARROW;
	else if (!strncmp(range, "FULL", 4))
		params->range = RANGE_FULL;
	else if (!strncmp(range, "FULLPROTECT", 11))
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

	if (sscanf(str, "MAXUDP=%i", &maxudp) != 1) {
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

	if (sscanf(str, "par=%i:%i", &width, &height) != 2) {
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

	if (sscanf(str, "TROFF=%i", &troff) != 1) {
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

static enum sdp_parse_err smpte2110_sdp_parse_fmtp_params(struct sdp_attr *a,
		char *params)
{
	struct {
		char *param;
		enum sdp_parse_err (*parser)(char *str,
			struct attr_params *params, uint32_t *err);
		int is_parsed;
	} attribute_param_list[] = {
		SDP_ATTR_PARAM_PARSE(sampling),
		SDP_ATTR_PARAM_PARSE(depth),
		SDP_ATTR_PARAM_PARSE(width),
		SDP_ATTR_PARAM_PARSE(height),
		SDP_ATTR_PARAM_PARSE(exactframerate),
		SDP_ATTR_PARAM_PARSE(colorimetry),
		SDP_ATTR_PARAM_PARSE(pm),
		SDP_ATTR_PARAM_PARSE(tp),
		SDP_ATTR_PARAM_PARSE(ssn),
		SDP_ATTR_PARAM_PARSE(interlace),
		SDP_ATTR_PARAM_PARSE(segmented),
		SDP_ATTR_PARAM_PARSE(tcs),
		SDP_ATTR_PARAM_PARSE(range),
		SDP_ATTR_PARAM_PARSE(maxudp),
		SDP_ATTR_PARAM_PARSE(par),
		SDP_ATTR_PARAM_PARSE(troff),
		SDP_ATTR_PARAM_PARSE(cmax),
	};
	struct attr_params p;
	char *token;
	char *tmp;
	struct smpte2110_media_attr_fmtp *smpte2110_fmtp;
	size_t slmax;

	smpte2110_fmtp = (struct smpte2110_media_attr_fmtp *)calloc(1,
		sizeof(struct smpte2110_media_attr_fmtp));
	if (!smpte2110_fmtp) {
		sdperr("Memory allocation");
		goto fail;
	}

	attribute_params_set_defaults(&p);

	smpte2110_fmtp->err = 0; /* no attribute params have been parsed */
	slmax = strnlen_s(params, STRNLENS_DEFAULT_MAX);
	while ((token = strtok_s(params, &slmax, ";", &tmp))) {
		size_t i;

		/* skip the white space(s) peceding the current token */
		while (IS_WHITESPACE(*token))
			token++;

		if (*token == '\n')
			break;

		for (i = 0; i < ARRAY_SIZE(attribute_param_list); i++) {
			size_t cmplen = strnlen_s(attribute_param_list[i].param,
				STRNLENS_DEFAULT_MAX);

			if (!strncasecmp(token, attribute_param_list[i].param,
					cmplen)) {
				break;
			}
		}

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
	if (!SMPTE_2110_ATTR_PARAM_REQUIRED(smpte2110_fmtp->err))
		goto fail;

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
	char *id[2] = {0};
	char *tmp;
	struct group_identification_tag **tag;
	struct sdp_attr_value_group *group = &a->value.group;
	size_t slmax = strnlen_s(params, STRNLENS_DEFAULT_MAX);
	int i;

	if (strncmp(value, "DUP", 3)) {
		sdperr("unsupported group semantic for media: %s", value);
		return SDP_PARSE_ERROR;
	}

	for (i = 0; i < 2; i++) {

		id[i] = strtok_s(params, &slmax, " \n", &tmp);
		if (!id[i] || (i ? *tmp : !*tmp)) {
			sdperr("group DUP attribute bad format");
			return SDP_PARSE_ERROR;
		}

		params = NULL;
	}

	for (tag = &group->tag, i = 0; i < 2; i++) {
		*tag = calloc(1, sizeof(struct group_identification_tag));
		if (!*tag || !((*tag)->identification_tag = strdup(id[i]))) {
			sdperr("memory allocation");
			goto fail;
		}

		group->num_tags++;
		tag = &(*tag)->next;
	}

	if (!(group->semantic = strdup(value))) {
		sdperr("memory allocation");
		goto fail;
	}

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

enum sdp_parse_err smpte2110_sdp_parse_specific(struct sdp_attr *a, char *attr,
		char *value, char *params)
{
	if (!strncmp(attr, "fmtp", 4))
		return smpte2110_sdp_parse_fmtp_params(a, params);

	if (!strncmp(attr, "group", 5))
		return smpte2110_sdp_parse_group(a, value, params);

	return SDP_PARSE_ERROR;
}

