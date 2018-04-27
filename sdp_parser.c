#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "sdp_parser.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define IS_WHITESPACE(_char_) ((_char_) == ' ' || (_char_) == '\t')

#define SDP_ATTR_PARAM_PARSE(_param_) \
	{ \
		.param = # _param_, \
		.parser = sdp_attr_param_parse_ ## _param_, \
		.is_parsed = 0 \
	}

#define SMPTE_2110_ATTR_PARAM_ERR_REQUIRED (SMPTE_ERR_SAMPLING | \
		SMPTE_ERR_DEPTH | SMPTE_ERR_WIDTH | SMPTE_ERR_HEIGHT | \
		SMPTE_ERR_EXACTFRAMERATE | SMPTE_ERR_COLORIMETRY | \
		SMPTE_ERR_PM | SMPTE_ERR_SSN)

#define SMPTE_2110_ATTR_PARAM_REQUIRED(_err_) \
	(((_err_) & SMPTE_2110_ATTR_PARAM_ERR_REQUIRED) == \
	 SMPTE_2110_ATTR_PARAM_ERR_REQUIRED)

struct attr_params {
	enum smpte_2110_sampling sampling;
	enum smpte_2110_depth depth;
	uint16_t width;
	uint16_t height;
	struct smpte_2110_fps exactframerate;
	struct smpte_2110_fps fps;
	enum smpte_2110_colorimetry colorimetry;
	enum smpte_2110_pm pm;
	int is_ssn;
	int is_interlace;
	int is_segmented;
	enum smpte_2110_tcs tcs;
	enum smpte_2110_range range;
	uint16_t maxudp;
	struct smpte_2110_par par;
};

static void sdperr(char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fprintf(stderr, "SDP parse error - ");
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	va_end(va);

	fflush(stderr);
}

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
		params->fps.is_integer = 0;
		goto exit;
	}

	ret = sscanf(str, "exactframerate=%i", &rate);
	if (ret == 1) {
		params->fps.is_integer = 1;
		goto exit;
	}

	sdperr("parameter format: %s", str);
	return SDP_PARSE_ERROR;

exit:
	params->fps.nominator = rate;
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
		params->colorimetry =  COLORIMETRY_BT601;
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
		params->pm =  PM_2110GPM;
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

static enum sdp_parse_err sdp_attr_param_parse_ssn(char *str,
		struct attr_params *params, uint32_t *err)
{
	if (strncmp(str, "SSN=ST2110-20:2017", strlen("SSN=ST2110-20:2017"))) {
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
		params->tcs =  TCS_SDR;
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
		params->range =  RANGE_NARROW;
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

	if (sscanf(str, "PAR=%i:%i", &width, &height) != 2) {
		sdperr("parameter format: %s", str);
		return SDP_PARSE_ERROR;
	}

	params->par.width = width;
	params->par.height = height;
	*err |= SMPTE_ERR_PAR;
	return SDP_PARSE_OK;
}


static enum sdp_parse_err sdp_parse_media_attr_params(char *line,
		struct media_attr_fmtp *fmtp)
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
		SDP_ATTR_PARAM_PARSE(ssn),
		SDP_ATTR_PARAM_PARSE(interlace),
		SDP_ATTR_PARAM_PARSE(segmented),
		SDP_ATTR_PARAM_PARSE(tcs),
		SDP_ATTR_PARAM_PARSE(range),
		SDP_ATTR_PARAM_PARSE(maxudp),
		SDP_ATTR_PARAM_PARSE(par),
	};
	struct attr_params params;
	char *token;

	attribute_params_set_defaults(&params);

	fmtp->err = 0; /* no attribute params have been parsed */
	while ((token = strtok(line, ";"))) {
		int i;

		/* skip the white space(s) peceding the current token */
		while (IS_WHITESPACE(*token))
			token++;

		for (i = 0; i < ARRAY_SIZE(attribute_param_list) &&
			strncmp(token, attribute_param_list[i].param,
				strlen(attribute_param_list[i].param)); i++);

		/* verify attribute is found in list */
		if (i == ARRAY_SIZE(attribute_param_list)) {
			sdperr("unknown attribute: %s", token);
			return SDP_PARSE_ERROR;
		}

		/* verify no multiple attribute signalling */
		if (attribute_param_list[i].is_parsed) {
			sdperr("multiple attribute signalling: %s",
				attribute_param_list[i].param);
			return SDP_PARSE_ERROR;
		}

		/* parse attribute */
		if (attribute_param_list[i].parser(token, &params,
				&fmtp->err) == SDP_PARSE_ERROR) {
			return SDP_PARSE_ERROR;
		}

		/* mark attriute as parsed */
		attribute_param_list[i].is_parsed = 1;
	}

	/* waver unsupported params */
	fmtp->err |= (SMPTE_ERR_COLORIMETRY | SMPTE_ERR_SSN);

	/* assert all required attriute parameters have been provided */
	if (!SMPTE_2110_ATTR_PARAM_REQUIRED(fmtp->err))
		return SDP_PARSE_ERROR;

	/* assert segmented parameter is not provided without interlace */
	if (params.is_segmented && ! params.is_interlace) {
		sdperr("cannot signal 'segmented' without 'interlace'");
		return SDP_PARSE_ERROR;
	}

	/* update output paprameters */
	fmtp->params.sampling = params.sampling;
	fmtp->params.depth = params.depth;
	fmtp->params.width = params.width;
	fmtp->params.height = params.height;
	fmtp->params.exactframerate = params.exactframerate;
	fmtp->params.colorimetry = params.colorimetry;
	fmtp->params.pm = params.pm;
	fmtp->params.signal = params.is_interlace ?
		params.is_segmented ? SIGNAL_PSF : SIGNAL_INTERLACE :
		SIGNAL_PROGRESSIVE;
	fmtp->params.tcs = params.tcs;
	fmtp->params.range = params.range;
	fmtp->params.maxudp = params.maxudp;
	fmtp->params.par = params.par;

	return SDP_PARSE_OK;
}

static char sdp_parse_descriptor_type(char *line)
{
	char descriptor;

	if (line[1] != '=') {
		sdperr("'x=' format not found");
		return 'x';
	}

	switch (*line) {
	/* session description */
	case 'v': /* Protocol Version */
	case 'o': /* Origin */
	case 's': /* Session Name */
	case 'i': /* Session Invormation */
	case 'u': /* URI */
	case 'e': /* Email Address */
	case 'p': /* Phone Number */
	case 'c': /* Connection Data */
	case 'b': /* Bandwidth */
	case 't': /* Timing */
	case 'r': /* Repeat Times */
	case 'z': /* Time Zones */
	case 'k': /* Encryption Keys */
	/* media description */
	case 'm': /* Media Descriptions */
	case 'a': /* Attributes */
		descriptor = *line;
		break;
	default:
		descriptor = 'x';
		sdperr("unsupported session descriptor: '%c='", *line);
		break;
	}

	return descriptor;
}

static enum sdp_parse_err sdp_parse_non_supported(char *line, char *descriptor)
{
	if (strncmp(line, descriptor, strlen(descriptor)))
		return SDP_PARSE_ERROR;

	return SDP_PARSE_NOT_SUPPORTED;
}

static enum sdp_parse_err sdp_parse_version(char *line)
{
	if (strncmp(line, "v=0", strlen("v=0")))
		return SDP_PARSE_ERROR;

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_originator(char *line)
{
	return sdp_parse_non_supported(line, "o=");
}

static enum sdp_parse_err sdp_parse_session_name(char *line)
{
	return sdp_parse_non_supported(line, "s=");
}

static enum sdp_parse_err sdp_parse_time_active(char *line)
{
	return sdp_parse_non_supported(line, "t=");
}

static enum sdp_parse_err sdp_parse_connection_information(char *line,
		struct sdp_connection_information *ci)
{
	char nettype[20];
	char addrtype[20];
	char addr[256];
	int ttl = 1;
	int ret;

	ret = sscanf(line, "c=%s %s %s/%d", nettype, addrtype, addr, &ttl);
	if (ret != 4) {
		ret = sscanf(line, "c=%s %s %s", nettype, addrtype, addr);
		if (ret != 3) {
			sdperr("c= bad format, %s", line);
			return SDP_PARSE_ERROR;
		}

		ttl = 1;
	}

	if (!strncmp(nettype, "IN", strlen("IN")))
		ci->nettype = SDP_CI_NETTYPE_IN;
	else
		ci->nettype = SDP_CI_NETTYPE_NOT_SUPPORTED;

	if (!strncmp(nettype, "IP4", strlen("IP4")))
		ci->addrtype = SDP_CI_ADDRTYPE_IPV4;
	else if (!strncmp(nettype, "IP6", strlen("IP6")))
		ci->addrtype = SDP_CI_ADDRTYPE_IPV6;
	else
		ci->addrtype = SDP_CI_ADDRTYPE_NOT_SUPPORTED;

	ci->sdp_ci_ttl = ttl;
	ci->is_used = 1;

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_media(char *line, struct sdp_media *media)
{
	int port;
	int num_ports;
	int fmt;

	if (sscanf(line, "video %d/%d RTP/AVP %d", &port, &num_ports, &fmt) !=
			3) {
		if (sscanf(line, "video %d RTP/AVP %d", &port, &fmt) != 2)
			return SDP_PARSE_ERROR;

		num_ports = 1;
	}

	media->type = SDP_MEDIA_TYPE_VIDEO;
	media->port = port;
	media->num_ports = num_ports;
	media->proto = SDP_MEDIA_PROTO_RTP_AVP;
	media->fmt = fmt;

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_media_level_attr(char *line,
		struct sdp_media_description *media_descriptor)
{
	int fmt;

	if (!strncmp(line, "a=rtpmap:", strlen("a=rtpmap:"))) {
		if (sscanf(line, "a=rtpmap:%d raw/90000", &fmt) != 1 ||
				fmt != media_descriptor->media.fmt) {
			sdperr("a=rtpmap:%d - wrong format", fmt);
			return SDP_PARSE_ERROR;
		}
	} else if (!strncmp(line, "a=fmtp:", strlen("a=fmtp:"))) {
		char *token;
		
		token = strtok(line, " ");
		if (!token) {
			sdperr("could not tokenize a=fmtp:<val>");
			return SDP_PARSE_ERROR;
		}

	 	if (sscanf(token, "a=fmtp:%d", &fmt) != 1) {
			sdperr("a=fmtp:<val> - could not extract <val> from"
				"%s", token);
			return SDP_PARSE_ERROR;
		}

		if (fmt != media_descriptor->media.fmt) {
			sdperr("a=fmtp:%d - wrong format", fmt);
			return SDP_PARSE_ERROR;
		}

		/* parse parameters */
		line = NULL;
		if (sdp_parse_media_attr_params(line,
				&media_descriptor->fmtp) == SDP_PARSE_ERROR) {
			return SDP_PARSE_ERROR;
		}
	} else {
		return SDP_PARSE_NOT_SUPPORTED;
	}

	return SDP_PARSE_OK;
}

enum sdp_parse_err smpte_2110_sdp_session_parse(FILE *sdp,
	struct sdp_session_description *session)
{
	enum sdp_parse_err err = SDP_PARSE_ERROR;
	char *line = NULL;
	size_t len = 0;

	/* parse v= */
	if (!getline(&line, &len, sdp) ||
			sdp_parse_version(line) == SDP_PARSE_ERROR) {
		goto fail;
	}

	/* parse o= (not supported) */
	if (!getline(&line, &len, sdp) ||
			sdp_parse_originator(line) == SDP_PARSE_ERROR) {
		goto fail;
	}

	/* parse s= (not supported) */
	if (!getline(&line, &len, sdp) ||
			sdp_parse_session_name(line) == SDP_PARSE_ERROR) {
		goto fail;
	}

	if (!getline(&line, &len, sdp))
		goto fail;

	/* parse i=* (not supported) */
	if (sdp_parse_descriptor_type(line) == 'i') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse u=* (not supported) */
	if (sdp_parse_descriptor_type(line) == 'u') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse e=* (not supported) */
	if (sdp_parse_descriptor_type(line) == 'e') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse p=* (not supported) */
	if (sdp_parse_descriptor_type(line) == 'p') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse c=* */
	if (sdp_parse_descriptor_type(line) == 'c') {
		if (sdp_parse_connection_information(line, &session->ci) ==
				SDP_PARSE_ERROR) {
			goto fail;
		}

		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse b=* (not supported) */
	if (sdp_parse_descriptor_type(line) == 'b') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse t= (not supported) */
	if (sdp_parse_time_active(line) == SDP_PARSE_ERROR)
		goto fail;

	if (!getline(&line, &len, sdp))
		goto fail;

	/* parse v=* (not supported) */
	if (sdp_parse_descriptor_type(line) == 'v') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse z=* (not supported) */
	if (sdp_parse_descriptor_type(line) == 'z') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse k=* (not supported) */
	if (sdp_parse_descriptor_type(line) == 'k') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse session-level a=* (not supported) */
	while (sdp_parse_descriptor_type(line) == 'a') {
		if (!getline(&line, &len, sdp))
			goto fail;
	}

	/* parse media-level description */
	do {
		struct sdp_media_description *media_descriptor;

		if (sdp_parse_descriptor_type(line) != 'm')
			goto fail;

		if (!(media_descriptor = calloc(1,
				sizeof(struct sdp_media_description)))) {
			goto fail;
		}

		/* parse m= */
		if (sdp_parse_media(line, &media_descriptor->media) ==
				SDP_PARSE_ERROR) {
			goto fail;
		}

		if (!getline(&line, &len, sdp))
			goto fail;

		/* parse i=* (not supported) */
		if (sdp_parse_descriptor_type(line) != 'i') {
			if (!getline(&line, &len, sdp))
				goto fail;
		}

		/* parse c=* */
		if (sdp_parse_descriptor_type(line) != 'c') {
			if (sdp_parse_connection_information(line,
				&media_descriptor->ci) == SDP_PARSE_ERROR) {
				goto fail;
			}

			if (!getline(&line, &len, sdp))
				goto fail;
		}

		/* parse b=* (not supported) */
		if (sdp_parse_descriptor_type(line) != 'b') {
			if (!getline(&line, &len, sdp))
				goto fail;
		}

		/* parse k=* (not supported) */
		if (sdp_parse_descriptor_type(line) != 'k') {
			if (!getline(&line, &len, sdp))
				goto fail;
		}

		/* parse media-level a=* */
		while (line && sdp_parse_descriptor_type(line) != 'a') {
			if (sdp_parse_media_level_attr(line,
					media_descriptor) == SDP_PARSE_ERROR) {
				goto fail;
			}

			getline(&line, &len, sdp);
		}

		/* add media_descriptor to session */
		media_descriptor->next = session->media;
		session->media = media_descriptor;
	} while (getline(&line, &len, sdp));

	err = SDP_PARSE_OK;
	goto exit;

fail:
	while (session->media) {
		struct sdp_media_description *media_descriptor;
		
		media_descriptor = session->media;
		session->media = session->media->next;
		free(media_descriptor);
	}

exit:
	free(line);
	return err;
}

