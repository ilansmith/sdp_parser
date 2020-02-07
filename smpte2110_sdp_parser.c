#include <stdlib.h>
#include <string.h>
#include "smpte2110_sdp_parser.h"
#include "sdp_field.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#define SMPTE_2110_ATTR_PARAM_ERR_REQUIRED (SMPTE_ERR_SAMPLING | \
		SMPTE_ERR_DEPTH | SMPTE_ERR_WIDTH | SMPTE_ERR_HEIGHT | \
		SMPTE_ERR_EXACTFRAMERATE | SMPTE_ERR_COLORIMETRY | \
		SMPTE_ERR_PM | SMPTE_ERR_TP | SMPTE_ERR_SSN)

#define IS_PARAM_REQUIRED(_mask_, _err_) (_mask_ & (1 << (_err_)) ? 1 : 0)

#define SMPTE2110_20_FMTP_PARAMS_NUM 17
#define SMPTE2110_40_FMTP_PARAMS_NUM 2

struct param_parse_info {
	char *name;
	enum sdp_parse_err (*parser)(char *str, void *params);
	unsigned int occurrences;
	unsigned int max_occurrences;
};

#define SMPTE_2110_FMTP_TABLE_START(_table_) \
	struct param_parse_info _table_[] = {
#define SMPTE_2110_FMTP_MULTI_ENTRY(_param_, _max_occurences_) \
	{ # _param_, sdp_attr_param_parse_## _param_, 0, _max_occurences_ },
#define SMPTE_2110_FMTP_NUM_ENTRY(_param_) \
	SMPTE_2110_FMTP_MULTI_ENTRY(_param_, 1)
#define SMPTE_2110_FMTP_TABLE_END };

#define UNLIMITED -1

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

static enum sdp_parse_err sdp_parse_params(void *result,
		char *input, struct param_parse_info *attribute_param_list,
		size_t list_size, uint32_t required_params)
{
	char *token;
	struct param_parse_info *param = NULL;
	size_t i;

	if (!input)
		input = "";

	while ((token = strtok(input, ";"))) {
		/* skip the white space(s) peceding the current token */
		while (IS_WHITESPACE(*token))
			token++;

		if (!*token)
			break;

		/* Find attribute index in list */
		for (i = 0; i < list_size; i++) {
			param = &attribute_param_list[i];
			if (!strncasecmp(token, param->name,
					strlen(param->name)))
				break;
		}
		if (i == list_size)
			return sdprerr("unknown attribute: %s", token);

		/* verify no multiple attribute signaling */
		if (param->occurrences == param->max_occurrences)
			return sdprerr("multiple attribute signaling: %s "
				"(%u allowed)", param->name,
				param->max_occurrences);

		/* parse attribute */
		if (param->parser(token, result) == SDP_PARSE_ERROR)
			return sdprerr("failed to parse parameter %s",
					param->name);

		/* mark attriute as parsed */
		param->occurrences += 1;
		input = NULL;
	}

	/* assert all required attributes parameters have been provided */
	for (i = 0; i < list_size; i++) {
		param = &attribute_param_list[i];
		if (IS_PARAM_REQUIRED(required_params, i) &&
				(param->occurrences == 0))
			return sdprerr("missing required parameter: %s",
					param->name);
	}
	return SDP_PARSE_OK;
}

/* attribute parsers */

static enum sdp_parse_err sdp_attr_param_parse_sampling(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	unsigned int i;
	int a;
	int b;
	int c;
	struct {
		char *string;
		enum smpte_2110_sampling value;
	} sampling_strings[] = {
		{ "RGB", SAMPLING_RGB },
		{ "XYZ", SAMPLING_XYZ },
		{ "KEY", SAMPLING_KEY },
	};
	struct {
		char *prefix;
		enum smpte_2110_sampling values[3];
	} sampling[] = {
		{
			"YCbCr",
			{
				SAMPLING_YCbCr_444,
				SAMPLING_YCbCr_422,
				SAMPLING_YCbCr_420
			}
		},
		{
			"CLYCbCr",
			{
				SAMPLING_CLYCbCr_444,
				SAMPLING_CLYCbCr_422,
				SAMPLING_CLYCbCr_420
			}
		},
		{
			"ICtCp",
			{
				SAMPLING_ICtCp_444,
				SAMPLING_ICtCp_422,
				SAMPLING_ICtCp_420
			}
		}
	};

	for (i = 0; i < ARRAY_SIZE(sampling_strings); i++) {
		char parameter[13];

		snprintf(parameter, sizeof(parameter), "sampling=%s",
			sampling_strings[i].string);
		if (!strncmp(str, parameter, strlen(parameter))) {
			params->sampling = sampling_strings[i].value;
			goto exit;
		}
	}

	for (i = 0; i < ARRAY_SIZE(sampling); i++) {
		char prefix[8];

		if (sscanf(str, "sampling=%7[YCbrLItp]-%i:%i:%i", prefix, &a,
				&b, &c) == 4) {
			break;
		}
	}

	if (i == ARRAY_SIZE(sampling))
		goto err;

	if (a != 4)
		goto err;

	if (b == 4) {
		if (c == 4)
			params->sampling = sampling[i].values[0];
		else
			goto err;
	} else if (b == 2) {
		if (c == 2)
			params->sampling = sampling[i].values[1];
		else if (c == 0)
			params->sampling = sampling[i].values[2];
		else
			goto err;
	} else {
		goto err;
	}

exit:
	return SDP_PARSE_OK;

err:
	return sdprerr("parameter format: '%s'", str);
}

static enum sdp_parse_err sdp_attr_param_parse_depth(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	int depth;
	char f;
	int ret;

	ret = sscanf(str, "depth=%i%c", &depth, &f);
	if (ret != 1 && ret != 2)
		return sdprerr("parameter format: %s", str);

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

	return SDP_PARSE_OK;

err:
	return sdprerr("supported depth: 8, 10, 12, 16, 16f");
}

static enum sdp_parse_err sdp_attr_param_parse_width(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	uint32_t width;

	if (sscanf(str, "width=%u", &width) != 1)
		return sdprerr("parameter format: %s", str);

	if (width < 1 || 32767 < width)
		return sdprerr("width is in the range of: [1, 32767]");

	params->width = width;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_height(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	uint32_t height;

	if (sscanf(str, "height=%u", &height) != 1)
		return sdprerr("parameter format: %s", str);

	if (height < 1 || 32767 < height)
		return sdprerr("height is in the range of: [1, 32767]");

	params->height = height;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_exactframerate(char *str,
		void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	int ret;
	int nominator;
	int denominator;

	ret = sscanf(str, "exactframerate=%i/%i", &nominator, &denominator);
	if (ret == 2) {
		if (denominator != 1001)
			return sdprerr("bad format param value: %s", str);

		params->exactframerate.is_integer = 0;
		goto exit;
	}

	ret = sscanf(str, "exactframerate=%i", &nominator);
	if (ret == 1) {
		params->exactframerate.is_integer = 1;
		goto exit;
	}

	return sdprerr("parameter format: %s", str);

exit:
	params->exactframerate.nominator = nominator;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_colorimetry(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	char colorimetry[256];

	if (sscanf(str, "colorimetry=%s", colorimetry) != 1)
		return sdprerr("parameter format: %s", str);

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

	return SDP_PARSE_OK;

err:
	return sdprerr("colorimetry can be: BT601, BT709, BT2020, BT2100, "
		"ST2065_1, ST2065_3, UNSPECIFIED");
}

static enum sdp_parse_err sdp_attr_param_parse_pm(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	char pm[256];

	if (sscanf(str, "PM=%s", pm) != 1)
		return sdprerr("parameter format: %s", str);

	if (!strncmp(pm, "2110GPM", strlen("2110GPM")))
		params->pm = PM_2110GPM;
	else if (!strncmp(pm, "2110BPM", strlen("2110BPM")))
		params->pm = PM_2110BPM;
	else
		goto err;

	return SDP_PARSE_OK;

err:
	return sdprerr("PM can be: 2110GPM, 2110BPM");
}

static enum sdp_parse_err sdp_attr_param_parse_tp(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	char tp[256];

	if (sscanf(str, "TP=%s", tp) != 1)
		return sdprerr("parameter format: %s", str);

	if (!strncmp(tp, "2110TPNL", strlen("2110TPNL")))
		params->tp = TP_2110TPNL;
	else if (!strncmp(tp, "2110TPN", strlen("2110TPN")))
		params->tp = TP_2110TPN;
	else if (!strncmp(tp, "2110TPW", strlen("2110TPW")))
		params->tp = TP_2110TPW;
	else
		goto err;

	return SDP_PARSE_OK;

err:
	return sdprerr("TP can be: 2110TPN, 2110TPNL, 2110TPW");
}

static enum sdp_parse_err sdp_attr_param_parse_ssn(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	if (strncmp(str, "SSN=ST2110-20:2017", strlen("SSN=ST2110-20:2017")) &&
			strncmp(str, "SSN=\"ST2110-20:2017\"",
			strlen("SSN=\"ST2110-20:2017\"")))
		return sdprerr("parameter format: %s", str);

	params->is_ssn = 1;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_interlace(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	if (strncmp(str, "interlace", strlen("interlace")))
		return sdprerr("parameter format: interlace");

	params->is_interlace = 1;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_segmented(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	if (strncmp(str, "segmented", strlen("segmented")))
		return sdprerr("parameter format: segmented");

	params->is_segmented = 1;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_tcs(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	char tcs[256];

	if (sscanf(str, "TCS=%s", tcs) != 1)
		return sdprerr("parameter format: %s", str);

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

	return SDP_PARSE_OK;

err:
	return sdprerr("TCS can be: SDR, PQ, HLG, LINEAR, BT2100LINPQ, "
		"BT2100LINHLG, ST2065-1, ST428-1, DENSITY, UNSPECIFIED");
}

static enum sdp_parse_err sdp_attr_param_parse_range(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	char range[256];

	if (sscanf(str, "RANGE=%s", range) != 1)
		return sdprerr("parameter format: %s", str);

	if (!strncmp(range, "NARROW", strlen("NARROW")))
		params->range = RANGE_NARROW;
	else if (!strncmp(range, "FULL", strlen("FULL")))
		params->range = RANGE_FULL;
	else if (!strncmp(range, "FULLPROTECT", strlen("FULLPROTECT")))
		params->range = RANGE_FULLPROTECT;
	else
		goto err;

	return SDP_PARSE_OK;

err:
	return sdprerr("RANGE can be: NARROW, FULL, FULLPROTECT");
}

static enum sdp_parse_err sdp_attr_param_parse_maxudp(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	uint32_t maxudp;

	if (sscanf(str, "MAXUDP=%u", &maxudp) != 1)
		return sdprerr("parameter format: %s", str);

	if (maxudp != 1460 && maxudp != 8960)
		goto err;

	params->maxudp = maxudp;
	return SDP_PARSE_OK;

err:
	return sdprerr("MAXUDP can be: 1460, 8960");
}

static enum sdp_parse_err sdp_attr_param_parse_par(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	uint32_t width;
	uint32_t height;

	if (sscanf(str, "PAR=%u:%u", &width, &height) != 2)
		return sdprerr("parameter format: %s", str);

	params->par.width = width;
	params->par.height = height;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_troff(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	uint32_t troff;

	if (sscanf(str, "TROFF=%u", &troff) != 1)
		return sdprerr("parameter format: %s", str);

	params->troff = troff;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_cmax(char *str, void *res)
{
	struct attr_params *params = (struct attr_params*)res;
	int cmax;

	if (sscanf(str, "CMAX=%i", &cmax) != 1)
		return sdprerr("parameter format: %s", str);

	params->cmax = cmax;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err smpte2110_20_parse_fmtp_params(
		struct interpretable *field, char *input)
{
	struct attr_params p;
	struct smpte2110_media_attr_fmtp *smpte2110_fmtp;

	SMPTE_2110_FMTP_TABLE_START(attribute_param_list)
		SMPTE_2110_FMTP_NUM_ENTRY(sampling)
		SMPTE_2110_FMTP_NUM_ENTRY(depth)
		SMPTE_2110_FMTP_NUM_ENTRY(width)
		SMPTE_2110_FMTP_NUM_ENTRY(height)
		SMPTE_2110_FMTP_NUM_ENTRY(exactframerate)
		SMPTE_2110_FMTP_NUM_ENTRY(colorimetry)
		SMPTE_2110_FMTP_NUM_ENTRY(pm)
		SMPTE_2110_FMTP_NUM_ENTRY(tp)
		SMPTE_2110_FMTP_NUM_ENTRY(ssn)
		SMPTE_2110_FMTP_NUM_ENTRY(interlace)
		SMPTE_2110_FMTP_NUM_ENTRY(segmented)
		SMPTE_2110_FMTP_NUM_ENTRY(tcs)
		SMPTE_2110_FMTP_NUM_ENTRY(range)
		SMPTE_2110_FMTP_NUM_ENTRY(maxudp)
		SMPTE_2110_FMTP_NUM_ENTRY(par)
		SMPTE_2110_FMTP_NUM_ENTRY(troff)
		SMPTE_2110_FMTP_NUM_ENTRY(cmax)
	SMPTE_2110_FMTP_TABLE_END;

	attribute_params_set_defaults(&p);
	if (sdp_parse_params(&p, input, attribute_param_list,
			ARRAY_SIZE(attribute_param_list),
			SMPTE_2110_ATTR_PARAM_ERR_REQUIRED) != SDP_PARSE_OK)
		return sdprerr("failed to parse one or more parameters");
	/* assert segmented parameter is not provided without interlace */
	if (p.is_segmented && ! p.is_interlace)
		return sdprerr("cannot signal 'segmented' without 'interlace'");

 	smpte2110_fmtp = (struct smpte2110_media_attr_fmtp *)calloc(1,
 		sizeof(struct smpte2110_media_attr_fmtp));
	if (!smpte2110_fmtp)
		return sdprerr("Memory allocation");

	/* update output parameters */
	smpte2110_fmtp->params.sampling = p.sampling;
	smpte2110_fmtp->params.depth = p.depth;
	smpte2110_fmtp->params.width = p.width;
	smpte2110_fmtp->params.height = p.height;
	smpte2110_fmtp->params.exactframerate = p.exactframerate;
	smpte2110_fmtp->params.colorimetry = p.colorimetry;
	smpte2110_fmtp->params.pm = p.pm;
	smpte2110_fmtp->params.tp = p.tp;
	smpte2110_fmtp->params.signal = p.is_interlace ?
		p.is_segmented ? SIGNAL_PSF : SIGNAL_INTERLACE :
			SIGNAL_PROGRESSIVE;
	smpte2110_fmtp->params.tcs = p.tcs;
	smpte2110_fmtp->params.range = p.range;
	smpte2110_fmtp->params.maxudp = p.maxudp;
	smpte2110_fmtp->params.par = p.par;

	field->as.as_ptr = smpte2110_fmtp;
	field->dtor = free;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_did_sdid(char *str, void *res)
{
	unsigned int c1, c2;
	struct smpte2110_40_fmtp_params *params =
			(struct smpte2110_40_fmtp_params*)res;

	if (sscanf(str, "DID_SDID={0x%x,0x%x}", &c1, &c2) != 2)
		return sdprerr("parameter format: '%s'", str);

	struct smpte2110_40_did_sdid *did = (struct smpte2110_40_did_sdid *)
		calloc(1, sizeof(struct smpte2110_40_did_sdid));
	if (!did)
		return sdprerr("memory allocation");

	did->code_1 = c1;
	did->code_2 = c2;
	if (params->last_did)
		params->last_did->next = did;
	else
		params->dids = did;
	params->last_did = did;
       return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_attr_param_parse_vpid_code(char *str, void *res)
{
	struct smpte2110_40_fmtp_params *params =
			(struct smpte2110_40_fmtp_params*)res;

	if (sscanf(str, "VPID_Code=%u", &params->vpid_code) != 1)
		return sdprerr("parameter format: '%s'", str);
	return SDP_PARSE_OK;
}

static void smpte2110_40_free_fmtp_param(void *ptr)
{
	struct smpte2110_40_fmtp_params *params =
			(struct smpte2110_40_fmtp_params*)ptr;
	struct smpte2110_40_did_sdid *did, *tmp;

	if (!params)
		return;

	did = params->dids;
	while (did) {
		tmp = did->next;
		free(did);
		did = tmp;
	}
	free(params);
}

static enum sdp_parse_err smpte2110_40_parse_fmtp_params(
		struct interpretable *field, char *input)
{
	struct smpte2110_40_fmtp_params *params;

	SMPTE_2110_FMTP_TABLE_START(attribute_param_list)
		SMPTE_2110_FMTP_MULTI_ENTRY(did_sdid, UNLIMITED)
		SMPTE_2110_FMTP_NUM_ENTRY(vpid_code)
	SMPTE_2110_FMTP_TABLE_END;

	params = (struct smpte2110_40_fmtp_params *)calloc(1,
		sizeof(struct smpte2110_40_fmtp_params));
	if (!params)
		return sdprerr("Memory allocation");

	if (sdp_parse_params(params, input, attribute_param_list,
			ARRAY_SIZE(attribute_param_list), 0) != SDP_PARSE_OK) {
		smpte2110_40_free_fmtp_param(params);
		return sdprerr("failed to parse smpte2110-40 fmtp params");
	}

	field->as.as_ptr = params;
	field->dtor = smpte2110_40_free_fmtp_param;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err smpte2110_30_parse_bit_depth(
		struct interpretable *field, char *input)
{
	if (sdp_parse_long_long(&field->as.as_ll, &input[1]) != SDP_PARSE_OK) {
		return sdprerr("invalid bit-depth '%s': expected L<int>",
			input);
	}
	if (!field->as.as_ll)
		return sdprerr("invalid bit-depth: 0");
	return SDP_PARSE_OK;
}

static enum sdp_parse_err smpte2110_30_parse_num_channels(
		struct interpretable *field, char *input)
{
	if (!input) {
		field->as.as_ll = 1;
		return SDP_PARSE_OK;
	}
	if (sdp_parse_long_long(&field->as.as_ll, input) != SDP_PARSE_OK) {
		return sdprerr("invalid num-channels '%s': expected <int>",
			input);
	}
	if (field->as.as_ll == 0)
		return sdprerr("invalid num-channels: 0");
	return SDP_PARSE_OK;
}

static enum sdp_parse_err smpte2110_30_parse_channel_order(
		struct interpretable *field, char *input)
{
	char *token;
	size_t co_len = strlen("channel-order");

	if (!input) {
		field->as.as_str = NULL;
		return SDP_PARSE_OK;
	}
	/* check channel-order= */
	token = strtok(input, "=");
	if (!token) {
		field->as.as_str = NULL;
		return SDP_PARSE_ERROR;
	}
	if (strncasecmp("channel-order", token, co_len)) {
		field->as.as_str = NULL;
		return SDP_PARSE_ERROR;
	}
	token += co_len + 1;
	if (!token) {
		field->as.as_str = NULL;
		return SDP_PARSE_ERROR;
	}
	if (sdp_parse_str(&field->as.as_str, token) != SDP_PARSE_OK)
		return sdprerr("invalid channel-order '%s'", token);
	if (*field->as.as_str == 0)
		return sdprerr("invalid channel_order: 0");
	else 
		field->dtor = free;

	return SDP_PARSE_OK;
}

static int get_required_attr_mask(int sub_type)
{
	switch (sub_type) {
	case SMPTE_2110_SUB_TYPE_20:
		return (1 << SDP_ATTR_FMTP);
	case SMPTE_2110_SUB_TYPE_30:
		return 0;
	case SMPTE_2110_SUB_TYPE_40:
		return 0;
	default:
		return 0;
	}
}

static enum sdp_parse_err smpte2110_parse_rtpmap_encoding_name(
		struct sdp_media *media, struct sdp_attr *attr,
		struct interpretable *field, char *input)
{
	int *sub_type = &attr->value.rtpmap.fmt->sub_type;

	if (media->m.type == SDP_MEDIA_TYPE_VIDEO) {
		if (!strcmp(input, "raw")) {
			*sub_type = SMPTE_2110_SUB_TYPE_20;
		} else if (!strcmp(input, "smpte291")) {
			*sub_type = SMPTE_2110_SUB_TYPE_40;
			media->m.type = SDP_MEDIA_TYPE_TEXT;
		}
	} else if (media->m.type == SDP_MEDIA_TYPE_AUDIO) {
		if (!strncmp(input, "L16", strlen("L16")) ||
		    !strncmp(input, "L24", strlen("L24"))) {
			*sub_type = SMPTE_2110_SUB_TYPE_30;
			return smpte2110_30_parse_bit_depth(field, input);
		}
	}
	return sdp_parse_field_default(field, input);
}

static enum sdp_parse_err smpte2110_parse_rtpmap_encoding_parameters(
		struct sdp_media *media, struct sdp_attr *attr,
		struct interpretable *field, char *input)
{
	int sub_type = attr->value.rtpmap.fmt->sub_type;

	NOT_IN_USE(media);

	if (sub_type == SMPTE_2110_SUB_TYPE_30)
		return smpte2110_30_parse_num_channels(field, input);
	return sdp_parse_field_default(field, input);
}

static enum sdp_parse_err smpte2110_parse_fmtp_params(
		struct sdp_media *media, struct sdp_attr *attr,
		struct interpretable *field, char *input)
{
	int sub_type = attr->value.fmtp.fmt->sub_type;

	NOT_IN_USE(media);

	if (sub_type == SMPTE_2110_SUB_TYPE_20)
		return smpte2110_20_parse_fmtp_params(field, input);
	if (sub_type == SMPTE_2110_SUB_TYPE_30)
		return smpte2110_30_parse_channel_order(field, input);
	if (sub_type == SMPTE_2110_SUB_TYPE_40)
		return smpte2110_40_parse_fmtp_params(field, input);
	return sdp_parse_field_default(field, input);
}

static enum sdp_parse_err smpte2110_validate_media(struct sdp_media *media)
{
	if (!sdp_validate_sub_types(media))
		return SDP_PARSE_NOT_SUPPORTED;

	if (!sdp_validate_required_attributes(media, get_required_attr_mask))
		return SDP_PARSE_ERROR;
	return SDP_PARSE_OK;
}

static struct sdp_specific smpte2110_specific =
{
	"smpte2110",
	smpte2110_parse_fmtp_params,
	smpte2110_parse_rtpmap_encoding_name,
	smpte2110_parse_rtpmap_encoding_parameters,
	smpte2110_validate_media,
};

struct sdp_specific *smpte2110 = &smpte2110_specific;
