#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "sdp_parser.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define SKIP_WHITESPACES(_ptr_) ({ \
	do { \
		while ((*_ptr_) == ' ') \
			(_ptr_)++; \
	} while (0); \
	*_ptr_; \
})

static char *common_level_attr[] = {
	"recvonly",
	"sendrecv",
	"sendoly",
	"inactive",
	"sdplang",
	"lang",
};

static size_t sdp_getline(char **line, size_t *len, FILE *sdp)
{
	char *tmp;
	size_t ret;

	if (!*line)
		return getline(line, len, sdp);

	tmp = strdup(*line);
	ret = getline(line, len, sdp);
	if (!ret || !strcmp(tmp, *line)) {
		free(*line);
		*line = NULL;
		ret = 0;
	}

	free(tmp);
	return ret;
}

static char sdp_parse_descriptor_type(char *line)
{
	char descriptor;

	if (line[1] != '=') {
		sdperr("'x=' format not found");
		return 0;
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
		descriptor = 0;
		sdperr("unsupported session descriptor: '%c='", *line);
		break;
	}

	return descriptor;
}

static enum sdp_parse_err sdp_parse_non_supported(FILE *sdp, char **line,
		size_t *len, char *not_supported)
{
	if (!*line)
		return SDP_PARSE_OK;

	do {
		if (!sdp_parse_descriptor_type(*line))
			return SDP_PARSE_ERROR;

		if (!strchr(not_supported, **line))
			return SDP_PARSE_NOT_SUPPORTED;

		sdp_getline(line, len, sdp);

	} while (*line);

	return SDP_PARSE_NOT_SUPPORTED;
}

static enum sdp_parse_err sdp_parse_version(FILE *sdp, char **line, size_t *len,
		struct sdp_session_v *v)
{
	int version;
	char *ptr;
	char *endptr;

	if (!sdp_getline(line, len, sdp))
		return SDP_PARSE_ERROR;

	if (sdp_parse_descriptor_type(*line) != 'v')
		return SDP_PARSE_ERROR;

	ptr = *line + 2;
	version = strtol(ptr, &endptr, 10);
	if (*endptr && *endptr != '\n') {
		sdperr("bad version - %s", *line);
		return SDP_PARSE_ERROR;
	}

	v->version = version;

	if (!sdp_getline(line, len, sdp))
		return SDP_PARSE_ERROR;

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_connection_information(FILE *sdp,
		char **line, size_t *len, struct sdp_connection_information *c)
{
	char *nettype;
	char *addrtype;
	char *addr;
	char *ptr;
	char *tmp;
	int ttl = 1;

	if (strncmp(*line, "c=", 2))
		return SDP_PARSE_OK;

	ptr = *line + 2;
	nettype = strtok_r(ptr, " ", &tmp);
	if (!nettype) {
		sdperr("bad connection information nettype");
		return SDP_PARSE_ERROR;
	}
	addrtype = strtok_r(NULL, " ", &tmp);
	if (!addrtype) {
		sdperr("bad connection information addrtype");
		return SDP_PARSE_ERROR;
	}

	addr = strtok_r(NULL, "/", &tmp);
	if (!addr) {
		addr = tmp;
	} else {
		char *endptr;

		ttl = strtol(tmp, &endptr, 10);
		if (*endptr && *endptr != '\n') {
			sdperr("bad connection information ttl");
			return SDP_PARSE_ERROR;
		}
	}

	if (!strncmp(nettype, "IN", strlen("IN")))
		c->nettype = SDP_CI_NETTYPE_IN;
	else
		c->nettype = SDP_CI_NETTYPE_NOT_SUPPORTED;

	if (!strncmp(addrtype, "IP4", strlen("IP4")))
		c->addrtype = SDP_CI_ADDRTYPE_IPV4;
	else if (!strncmp(nettype, "IP6", strlen("IP6")))
		c->addrtype = SDP_CI_ADDRTYPE_IPV6;
	else
		c->addrtype = SDP_CI_ADDRTYPE_NOT_SUPPORTED;

	strncpy(c->sdp_ci_addr, addr, sizeof(c->sdp_ci_addr));
	c->sdp_ci_ttl = ttl;
	c->count = 1;

	sdp_getline(line, len, sdp);

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_media(FILE *sdp, char **line, size_t *len,
		struct sdp_media_m *media)
{
	char *type;
	char *proto;
	int port;
	int num_ports;
	int fmt;
	char *ptr;
	char *tmp;
	char *slash;
	char *endptr;
	struct sdp_media_fmt **smf = &media->fmt.next;
	enum sdp_parse_err err = SDP_PARSE_OK;

	if (strncmp(*line, "m=", 2)) {
		sdperr("bad media descriptor - m=");
		return SDP_PARSE_ERROR;
	}

	ptr = *line + 2;
	type = strtok_r(ptr, " ", &tmp);
	if (!type) {
		sdperr("bad media descriptor");
		return SDP_PARSE_ERROR;
	}
	slash = strchr(tmp, '/');
	port = strtol(strtok_r(NULL, " /", &tmp), &endptr, 10);
	if (*endptr && *endptr != '\n') {
		sdperr("bad media descriptor - port");
		return SDP_PARSE_ERROR;
	}

	if (slash + 1 == tmp) {
		num_ports = strtol(strtok_r(NULL, " ", &tmp), &endptr, 10);
		if (*endptr && *endptr != '\n') {
			sdperr("bad media descriptor - num_ports");
			return SDP_PARSE_ERROR;
		}
	} else {
		num_ports = 1;
	}

	proto = strtok_r(NULL, " ", &tmp);
	fmt = strtol(strtok_r(NULL, " \n", &tmp), &endptr, 10);
	if (*endptr && *endptr != '\n') {
		sdperr("bad media descriptor - fmt");
		return SDP_PARSE_ERROR;
	}

	if (!strncmp(type, "video", strlen("video"))) {
		media->type = SDP_MEDIA_TYPE_VIDEO;
	} else {
		media->type = SDP_MEDIA_TYPE_NOT_SUPPORTED;
		err = SDP_PARSE_NOT_SUPPORTED;
	}

	if (!strncmp(proto, "RTP/AVP", strlen("RTP/AVP"))) {
		media->proto = SDP_MEDIA_PROTO_RTP_AVP;
	} else {
		media->proto = SDP_MEDIA_PROTO_NOT_SUPPORTED;
		err = SDP_PARSE_NOT_SUPPORTED;
	}

	media->port = port;
	media->num_ports = num_ports;
	media->fmt.id = fmt;

	while (tmp && *tmp) {
		if (!(*smf = calloc(1, sizeof(struct sdp_media_fmt)))) {
			sdperr("memory acllocation");
			return SDP_PARSE_ERROR;
		}

		fmt = strtol(strtok_r(NULL, " \n", &tmp), &endptr, 10);
		if (*endptr && *endptr != '\n') {
			sdperr("bad media descriptor - fmt");
			return SDP_PARSE_ERROR;
		}
		(*smf)->id = fmt;
		smf = &(*smf)->next;
	}

	sdp_getline(line, len, sdp);

	return err;
}

static enum sdp_parse_err parse_attr_common(struct sdp_attr *a, char *attr,
		char *value, char *params)
{
	return SDP_PARSE_NOT_SUPPORTED;
}

static enum sdp_parse_err parse_attr_media(struct sdp_attr *a, char *attr,
		char *value, char *params,
		parse_attr_specific_t parse_attr_specific)
{
	char *endptr;

	if (!strncmp(attr, "rtpmap", strlen("rtpmap"))) {
		struct sdp_attr_value_rtpmap *rtpmap = &a->value.rtpmap;
		char *media_subtype, *clock_rate;

		media_subtype = strtok_r(params, "/", &clock_rate);

		if (!media_subtype || !clock_rate) {
			sdperr("attribute bad format - %s", attr);
			return SDP_PARSE_ERROR;
		}

		rtpmap->fmt = strtol(value, &endptr, 10);
		if (*endptr) {
			sdperr("attribute bad format - %s", attr);
			return SDP_PARSE_ERROR;
		}

		strncpy(rtpmap->media_subtype, media_subtype,
			sizeof(rtpmap->media_subtype));

		rtpmap->clock_rate = strtol(clock_rate, &endptr, 10);
		if (*endptr && *endptr != '\n') {
			sdperr("attribute bad format - %s", attr);
			return SDP_PARSE_ERROR;
		}

		a->type = SDP_ATTR_RTPMAP;
	} else if (!strncmp(attr, "fmtp", strlen("fmtp"))) {
		struct sdp_attr_value_fmtp *fmtp = &a->value.fmtp;
		char *endptr;

		fmtp->fmt = strtol(value, &endptr, 10);
		if (*endptr && *endptr != '\n') {
			sdperr("attribute bad format - %s", attr);
			return SDP_PARSE_ERROR;
		}

		if (*params && (!parse_attr_specific ||
				parse_attr_specific(a, attr, value, params) ==
				SDP_PARSE_ERROR)) {
			return SDP_PARSE_ERROR;
		}

		a->type = SDP_ATTR_FMTP;
	} else {
		a->type = SDP_ATTR_NOT_SUPPORTED;
		return SDP_PARSE_NOT_SUPPORTED;
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_attr(FILE *sdp, char **line, size_t *len,
		struct sdp_media *media,
		char **attr_common, int attr_common_len,
		char **attr_level, int attr_level_len,
		enum sdp_parse_err (*parse_level)(struct sdp_attr *a,
			char *attr, char *value, char *params,
			parse_attr_specific_t parse_attr_specific),
		parse_attr_specific_t parse_attr_specific)
{
	struct sdp_attr **a = &media->a; /* a=* */
	char *attr;
	char *value = NULL;
	char *params = NULL;
	int is_attr = 0;
	int i;
	enum sdp_parse_err err;
	char *ptr = *line;
	char *tmp;

	while (*line && **line != '\n' &&
			sdp_parse_descriptor_type(*line) == 'a') {
		ptr = *line + 2;
		is_attr = 0;

		attr = strtok_r(ptr, ":", &tmp);
		if (*tmp)
			value = strtok_r(NULL, " ", &tmp);
		if (*tmp)
			params = tmp;

		*a = calloc(1, sizeof(struct sdp_attr));
		if (!*a) {
			sdperr("memory acllocation");
			return SDP_PARSE_ERROR;
		}

		for (i = 0; !is_attr && i < attr_common_len; i++) {
			if (!strncmp(attr, attr_common[i],
					strlen(attr_common[i]))) {
				if ((err = parse_attr_common(*a, attr,
						value, params)) !=
						SDP_PARSE_OK) {
					free(*a);
					return err;
				}

				is_attr = 1;
			}
		}

		for (i = 0; !is_attr && i < attr_level_len; i++) {
			if (!strncmp(attr, attr_level[i],
					strlen(attr_level[i]))) {
				if ((err = parse_level(*a, attr, value,
						params, parse_attr_specific)) !=
						SDP_PARSE_OK) {
					free(*a);
					return err;
				}

				is_attr = 1;
			}
		}

		if (!is_attr && parse_attr_specific) {
			(*a)->type = SDP_ATTR_SPECIFIC;
			is_attr =
				parse_attr_specific(*a, attr, value, params) !=
				SDP_PARSE_ERROR;
		}

		/* XXX non supported attributes are not handled/reported */
		if (is_attr) {
			a = &(*a)->next;
		} else {
			free(*a);
			*a = NULL;
		}

		sdp_getline(line, len, sdp);
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_media_level_attr(FILE *sdp, char **line,
		size_t *len, struct sdp_media *media,
		parse_attr_specific_t parse_attr_specific)
{
	static char *media_level_attr[] = {
		"ptime",
		"maxptime",
		"rtpmap",
		"orient",
		"framerate",
		"quality",
		"fmtp",
	};

	return sdp_parse_attr(sdp, line, len, media,
		common_level_attr, ARRAY_SIZE(common_level_attr),
		media_level_attr, ARRAY_SIZE(media_level_attr),
		parse_attr_media, parse_attr_specific);
}

static void media_fmt_free(struct sdp_media_fmt *fmt)
{
	while (fmt) {
		struct sdp_media_fmt *tmp;

		tmp = fmt;
		fmt = fmt->next;
		free(tmp);
	}
}

static void sdp_attr_free(struct sdp_attr *attr)
{
	while (attr) {
		struct sdp_attr *tmp;

		tmp = attr;
		attr = attr->next;

		switch (tmp->type) {
		case SDP_ATTR_FMTP:
			if (tmp->value.fmtp.param_dtor) {
				tmp->value.fmtp.param_dtor(
					tmp->value.fmtp.params);
			}
			break;
		case SDP_ATTR_SPECIFIC:
			free(tmp->value.specific);
			break;
		default:
			break;
		}

		free(tmp);
	}
}

static void media_free(struct sdp_media *media)
{
	while (media) {
		struct sdp_media *tmp;

		tmp = media;
		media = media->next;

		media_fmt_free(tmp->m.fmt.next);
		sdp_attr_free(tmp->a);

		free(tmp);
	}
}

struct sdp_session *sdp_parser_init(char *path)
{
	struct sdp_session *session;

	session = (struct sdp_session*)calloc(1, sizeof(struct sdp_session));
	if (!session)
		return NULL;

	if (!(session->sdp = fopen(path, "r"))) {
		free(session);
		return NULL;
	}

	return session;
}

void sdp_parser_uninit(struct sdp_session *session)
{
	fclose(session->sdp);
	media_free(session->media);
	free(session);
}

enum sdp_parse_err sdp_session_parse(struct sdp_session *session,
		parse_attr_specific_t parse_attr_specific)
{
	enum sdp_parse_err err = SDP_PARSE_ERROR;
	char *line = NULL;
	size_t len = 0;
	FILE *sdp = session->sdp;

	/* parse v= */
	if (sdp_parse_version(sdp, &line, &len, &session->v) ==
			SDP_PARSE_ERROR) {
		goto exit;
	}

	/* skip parsing of non supported session-level descriptors */
	if (sdp_parse_non_supported(sdp, &line, &len, "osiuep") ==
			SDP_PARSE_ERROR) {
		goto exit;
	}

	/* nothing except for (t=[v=]) is compulsory from here on */
	if (!line) {
		err = SDP_PARSE_OK;
		goto exit;
	}

	/* parse c=* */
	if (sdp_parse_connection_information(sdp, &line, &len, &session->c) ==
			SDP_PARSE_ERROR) {
		goto exit;
	}

	if (!line) {
		err = SDP_PARSE_OK;
		goto exit;
	}

	/* skip parsing of non supported session-level descriptors */
	if (sdp_parse_non_supported(sdp, &line, &len, "btvuezka") ==
			SDP_PARSE_ERROR) {
		goto exit;
	}

	if (!line) {
		err = SDP_PARSE_OK;
		goto exit;
	}

	/* parse media-level description */

	do {
		struct sdp_media *media;
		struct sdp_media **next;

		if (sdp_parse_descriptor_type(line) != 'm')
			goto exit;

		if (!(media= calloc(1, sizeof(struct sdp_media))))
			goto exit;

		/* parse m= */
		if (sdp_parse_media(sdp, &line, &len, &media->m) ==
				SDP_PARSE_ERROR) {
			goto exit;
		}
		if (!line)
			return SDP_PARSE_OK;

		/* skip parsing of non supported media-level descriptors */
		if (sdp_parse_non_supported(sdp, &line, &len, "i") ==
				SDP_PARSE_ERROR) {
			goto exit;
		}
		if (!line)
			return SDP_PARSE_OK;

		/* parse c=* */
		if (sdp_parse_connection_information(sdp, &line, &len,
				&media->c) == SDP_PARSE_ERROR) {
			goto exit;
		}
		if (!line)
			return SDP_PARSE_OK;

		/* skip parsing of non supported media-level descriptors */
		if (sdp_parse_non_supported(sdp, &line, &len, "bk") ==
				SDP_PARSE_ERROR) {
			goto exit;
		}
		if (!line)
			return SDP_PARSE_OK;

		/* parse media-level a=* */
		if (sdp_parse_media_level_attr(sdp, &line, &len, media,
				parse_attr_specific) == SDP_PARSE_ERROR) {
			goto exit;
		}

		/* add media to session */
		for (next = &session->media; *next; next = &(*next)->next);
		*next = media;
	} while (line && *line != '\n');

	err = SDP_PARSE_OK;
	goto exit;

exit:
	free(line);
	return err;
}

void sdperr(char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fprintf(stderr, "SDP parse error - ");
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	va_end(va);

	fflush(stderr);
}

