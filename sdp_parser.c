#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "sdp_parser.h"

#ifndef NOT_IN_USE
#define NOT_IN_USE(a) ((void)(a))
#endif

#define SKIP_WHITESPACES(_ptr_) ({ \
	do { \
		while ((*_ptr_) == ' ') \
			(_ptr_)++; \
	} while (0); \
	*_ptr_; \
})

#define SDPOUT(func_suffix, level) \
	void sdp ## func_suffix(char *fmt, ...) \
	{ \
		va_list va; \
		va_start(va, fmt); \
		sdpout(level, fmt, va); \
		va_end(va); \
	}

static int is_line_delim(char c)
{
	return c == '\r' || c == '\n';
}

static ssize_t sdp_getline(char **line, size_t *len, sdp_stream_t sdp)
{
	char *tmp;
	ssize_t ret;

	if (!*line)
		return sdp_stream_getline(line, len, sdp);

	tmp = strdup(*line);
	ret = sdp_stream_getline(line, len, sdp);
	if (!ret || !strcmp(tmp, *line)) {
		free(*line);
		*line = NULL;
		ret = 0;
	}

	free(tmp);
	if (ret == -1)
		sdperr("readline error");
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

static enum sdp_parse_err sdp_parse_non_supported(sdp_stream_t sdp, char **line,
		size_t *len, char *not_supported)
{
	if (!*line)
		return SDP_PARSE_OK;

	do {
		if (!sdp_parse_descriptor_type(*line))
			return SDP_PARSE_ERROR;

		if (!strchr(not_supported, **line))
			return SDP_PARSE_NOT_SUPPORTED;

		if (sdp_getline(line, len, sdp) == -1)
			return SDP_PARSE_ERROR;

	} while (*line);

	return SDP_PARSE_NOT_SUPPORTED;
}

static enum sdp_parse_err sdp_parse_version(sdp_stream_t sdp, char **line,
		size_t *len, struct sdp_session_v *v)
{
	int version;
	char *ptr;
	char *endptr;
	ssize_t sz;

	sz = sdp_getline(line, len, sdp);
	if (sz == -1)
		return SDP_PARSE_ERROR;

	if (!sz || sdp_parse_descriptor_type(*line) != 'v') {
		sdperr("missing required sdp version");
		return SDP_PARSE_ERROR;
	}

	ptr = *line + 2;
	version = strtol(ptr, &endptr, 10);
	if (*endptr && !is_line_delim(*endptr)) {
		sdperr("bad version - %s", *line);
		return SDP_PARSE_ERROR;
	}

	v->version = version;

	sz = sdp_getline(line, len, sdp);
	if (sz == -1)
		return SDP_PARSE_ERROR;
	if (!sz) {
		sdperr("no more sdp fields after version");
		return SDP_PARSE_ERROR;
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_connection_information(sdp_stream_t sdp,
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
		if (*endptr && !is_line_delim(*endptr)) {
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

	if (sdp_getline(line, len, sdp) == -1)
		return SDP_PARSE_ERROR;

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_media(sdp_stream_t sdp, char **line,
		size_t *len, struct sdp_media_m *media)
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
	if (*endptr && !is_line_delim(*endptr)) {
		sdperr("bad media descriptor - port");
		return SDP_PARSE_ERROR;
	}

	if (slash + 1 == tmp) {
		num_ports = strtol(strtok_r(NULL, " ", &tmp), &endptr, 10);
		if (*endptr && !is_line_delim(*endptr)) {
			sdperr("bad media descriptor - num_ports");
			return SDP_PARSE_ERROR;
		}
	} else {
		num_ports = 1;
	}

	proto = strtok_r(NULL, " ", &tmp);
	fmt = strtol(strtok_r(NULL, " \r\n", &tmp), &endptr, 10);
	if (*endptr && !is_line_delim(*endptr)) {
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
		if (!(*smf = (struct sdp_media_fmt*)calloc(1,
                		sizeof(struct sdp_media_fmt)))) {
			sdperr("memory acllocation");
			return SDP_PARSE_ERROR;
		}

		fmt = strtol(strtok_r(NULL, " \r\n", &tmp), &endptr, 10);
		if (*endptr && !is_line_delim(*endptr)) {
			sdperr("bad media descriptor - fmt");
			return SDP_PARSE_ERROR;
		}
		(*smf)->id = fmt;
		smf = &(*smf)->next;
	}

	if (sdp_getline(line, len, sdp) == -1)
		return SDP_PARSE_ERROR;

	return err;
}

static enum sdp_parse_err parse_attr_common(struct sdp_attr *a, char *attr,
		char *value, char *params,
		parse_attr_specific_t parse_attr_specific)
{
	NOT_IN_USE(a);
	NOT_IN_USE(attr);
	NOT_IN_USE(value);
	NOT_IN_USE(params);
	NOT_IN_USE(parse_attr_specific);

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_attr(sdp_stream_t sdp, char **line,
		size_t *len, struct sdp_attr **a, char **attr_level,
		enum sdp_parse_err (*parse_level)(struct sdp_attr *a,
			char *attr, char *value, char *params,
			parse_attr_specific_t parse_attr_specific),
		parse_attr_specific_t parse_attr_specific)
{
	char **supported_attr;
	char *attr;
	char *value;
	char *params;
	enum sdp_parse_err err;
	char *ptr = *line;
	char *tmp;

	char *common_level_attr[] = {
#if 0
		"recvonly",
		"sendrecv",
		"sendoly",
		"inactive",
		"sdplang",
		"lang",
#endif
		NULL
	};

	while (*line && !is_line_delim(**line) &&
			sdp_parse_descriptor_type(*line) == 'a') {
		value = NULL;
		params = NULL;
		ptr = *line + 2;

		attr = strtok_r(ptr, ":\r\n", &tmp);
		if (*tmp)
			value = strtok_r(NULL, " ", &tmp);
		if (*tmp)
			params = tmp;

		*a = (struct sdp_attr*)calloc(1, sizeof(struct sdp_attr));
		if (!*a) {
			sdperr("memory acllocation");
			return SDP_PARSE_ERROR;
		}

		/* try to find a supported attribute in the session/media
		 * common list */
		for (supported_attr = common_level_attr; *supported_attr &&
			strcmp(*supported_attr, attr); supported_attr++);
		if (*supported_attr) {
			err = parse_attr_common(*a, *supported_attr, value,
				params, parse_attr_specific);
			if (err == SDP_PARSE_ERROR) {
				free(*a);
				*a = NULL;
				sdperr("parsing attribute: %s", attr);
				return SDP_PARSE_ERROR;
			}

			a = &(*a)->next;
			if (sdp_getline(line, len, sdp) == -1)
				return SDP_PARSE_ERROR;
			continue;
		}

		/* try to find supported attribute in current level list */
		for (supported_attr = attr_level; *supported_attr &&
			strcmp(*supported_attr, attr); supported_attr++);
		if (*supported_attr) {
			err = parse_level(*a, *supported_attr, value, params,
					parse_attr_specific);
			if (err == SDP_PARSE_ERROR) {
				free(*a);
				*a = NULL;
				sdperr("parsing attribute: %s", attr);
				return SDP_PARSE_ERROR;
			}

			a = &(*a)->next;
			if (sdp_getline(line, len, sdp) == -1)
				return SDP_PARSE_ERROR;
			continue;
		}

		/* attribute is not supported */
		free(*a);
		*a = NULL;
		if (sdp_getline(line, len, sdp) == -1)
			return SDP_PARSE_ERROR;
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err parse_attr_session(struct sdp_attr *a, char *attr,
		char *value, char *params,
		parse_attr_specific_t parse_attr_specific)
{
	if (!strncmp(attr, "group", strlen("group"))) {
		/* currently not supporting the general case */
		if (!parse_attr_specific)
			return SDP_PARSE_NOT_SUPPORTED;

		return parse_attr_specific(a, attr, value, params);
	} else {
		a->type = SDP_ATTR_NOT_SUPPORTED;
		return SDP_PARSE_NOT_SUPPORTED;
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_session_level_attr(sdp_stream_t sdp,
		char **line, size_t *len, struct sdp_attr **a,
		parse_attr_specific_t parse_attr_specific)
{
	static char *session_level_attr[] = {
		"group",
		NULL
	};

	return sdp_parse_attr(sdp, line, len, a, session_level_attr,
		parse_attr_session, parse_attr_specific);
}

static enum sdp_parse_err sdp_parse_attr_source_filter(
		struct sdp_attr_value_source_filter *source_filter,
		char *value, char *params)
{
	char *nettype;
	char *addrtype;
	char *dst_addr;
	char *src_addr;
	char *tmp;
	struct source_filter_src_addr src_list;
	int src_list_len;

	/* filter-mode */
	if (!strncmp(value, "incl", strlen("incl"))) {
		source_filter->mode = SDP_ATTR_SRC_FLT_INCL;
	} else if (!strncmp(value, "excl", strlen("excl"))) {
		source_filter->mode = SDP_ATTR_SRC_FLT_EXCL;
	} else {
		sdperr("bad source-filter mode type");
		return SDP_PARSE_ERROR;
	}

	/* filter-spec */
	nettype = strtok_r(params, " ", &tmp);
	if (!nettype) {
		sdperr("bad source-filter nettype");
		return SDP_PARSE_ERROR;
	}

	addrtype = strtok_r(NULL, " ", &tmp);
	if (!addrtype) {
		sdperr("bad source-filter addrtype");
		return SDP_PARSE_ERROR;
	}

	dst_addr = strtok_r(NULL, " ", &tmp);
	if (!dst_addr) {
		sdperr("bad source-filter dst-addr");
		return SDP_PARSE_ERROR;
	}

	src_addr = strtok_r(NULL, " \r\n", &tmp);
	if (!src_addr) {
		sdperr("bad source-filter src-addr");
		return SDP_PARSE_ERROR;
	}
	memset(&src_list, 0, sizeof(struct source_filter_src_addr));
	strncpy(src_list.addr, src_addr, sizeof(src_list.addr));
	src_list.next = NULL;
	src_list_len = 1;

	while (*tmp) {
		/* limitation:
		 * rfc4570 defines a list of source addresses.
		 * The current implementation supports only a single source
		 * address */
		sdpwarn("source filter attribute currently supports a "
			"single source address");
		*tmp = 0;
	}

	if (!strncmp(nettype, "IN", strlen("IN")))
		source_filter->spec.nettype = SDP_CI_NETTYPE_IN;
	else
		source_filter->spec.nettype = SDP_CI_NETTYPE_NOT_SUPPORTED;

	if (!strncmp(addrtype, "IP4", strlen("IP4")))
		source_filter->spec.addrtype = SDP_CI_ADDRTYPE_IPV4;
	else if (!strncmp(nettype, "IP6", strlen("IP6")))
		source_filter->spec.addrtype = SDP_CI_ADDRTYPE_IPV6;
	else
		source_filter->spec.addrtype = SDP_CI_ADDRTYPE_NOT_SUPPORTED;

	strncpy(source_filter->spec.dst_addr, dst_addr,
		sizeof(source_filter->spec.dst_addr));

	memcpy(&source_filter->spec.src_list, &src_list,
		sizeof(struct source_filter_src_addr));

	source_filter->spec.src_list_len = src_list_len;
	return SDP_PARSE_OK;
}

static enum sdp_parse_err parse_attr_media(struct sdp_attr *a, char *attr,
		char *value, char *params,
		parse_attr_specific_t parse_attr_specific)
{
	char *endptr;

	if (!strncmp(attr, "rtpmap", strlen("rtpmap"))) {
		struct sdp_attr_value_rtpmap *rtpmap = &a->value.rtpmap;
		char *media_subtype, *clock_rate;

		a->type = SDP_ATTR_RTPMAP;

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
		if (*endptr && !is_line_delim(*endptr)) {
			sdperr("attribute bad format - %s", attr);
			return SDP_PARSE_ERROR;
		}
	} else if (!strncmp(attr, "fmtp", strlen("fmtp"))) {
		struct sdp_attr_value_fmtp *fmtp = &a->value.fmtp;
		char *endptr;

		a->type = SDP_ATTR_FMTP;

		fmtp->fmt = strtol(value, &endptr, 10);
		if (*endptr && !is_line_delim(*endptr)) {
			sdperr("attribute bad format - %s", attr);
			return SDP_PARSE_ERROR;
		}

		if (*params && (!parse_attr_specific ||
				parse_attr_specific(a, attr, value, params) ==
				SDP_PARSE_ERROR)) {
			return SDP_PARSE_ERROR;
		}
	} else if (!strncmp(attr, "source-filter", strlen("source-filter"))) {
		struct sdp_attr_value_source_filter *source_filter;

		source_filter = &a->value.source_filter;
		a->type = SDP_ATTR_SOURCE_FILTER;

		if (sdp_parse_attr_source_filter(source_filter, value,
				params)) {
			sdperr("attribute bad format - %s", attr);
			return SDP_PARSE_ERROR;
		}
	} else if (!strncmp(attr, "mid", strlen("mid"))) {
		char *identification_tag;

		a->type = SDP_ATTR_MID;
		identification_tag = strtok(value, "\r\n");
		if (!identification_tag) {
			sdperr("attribute bad format - %s", attr);
			return SDP_PARSE_ERROR;
		}

		a->value.mid.identification_tag = strdup(value);
		if (!a->value.mid.identification_tag) {
			sdperr("failed to allocate memory for "
				"identification_tag: %s", value);
			return SDP_PARSE_ERROR;
		}
	} else {
		a->type = SDP_ATTR_NOT_SUPPORTED;
		return SDP_PARSE_NOT_SUPPORTED;
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_media_level_attr(sdp_stream_t sdp,
		char **line, size_t *len, struct sdp_attr **a,
		parse_attr_specific_t parse_attr_specific)
{
	static char *media_level_attr[] = {
#if 0
		"ptime",
		"maxptime",
		"orient",
		"framerate",
		"quality",
#endif
		"rtpmap",
		"fmtp",
		"source-filter",
		"mid",
		NULL
	};

	return sdp_parse_attr(sdp, line, len, a, media_level_attr,
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
		case SDP_ATTR_GROUP:
		{
			struct group_identification_tag *tag;

			while ((tag = tmp->value.group.tag)) {
				tmp->value.group.tag =
					tmp->value.group.tag->next;

				free(tag->identification_tag);
				free(tag);
			}

			free(tmp->value.group.semantic);
		}
		break;
		case SDP_ATTR_FMTP:
			if (tmp->value.fmtp.param_dtor) {
				tmp->value.fmtp.param_dtor(
					tmp->value.fmtp.params);
			}
			break;
		case SDP_ATTR_SOURCE_FILTER:
			free(tmp->value.source_filter.spec.src_list.next);
			break;
		case SDP_ATTR_MID:
			free(tmp->value.mid.identification_tag);
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

struct sdp_session *sdp_parser_init(enum sdp_stream_type type, void *ctx)
{
	struct sdp_session *session;

	session = (struct sdp_session*)calloc(1, sizeof(struct sdp_session));
	if (!session)
		return NULL;

	if (!(session->sdp = sdp_stream_open(type, ctx))) {
		free(session);
		return NULL;
	}

	return session;
}

void sdp_parser_uninit(struct sdp_session *session)
{
	sdp_stream_close(session->sdp);
	sdp_attr_free(session->a);
	media_free(session->media);
	free(session);
}

enum sdp_parse_err sdp_session_parse(struct sdp_session *session,
		parse_attr_specific_t parse_attr_specific)
{
	enum sdp_parse_err err = SDP_PARSE_ERROR;
	char *line = NULL;
	size_t len = 0;
	sdp_stream_t sdp = session->sdp;

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
	if (sdp_parse_non_supported(sdp, &line, &len, "btvuezk") ==
			SDP_PARSE_ERROR) {
		goto exit;
	}

	if (!line) {
		err = SDP_PARSE_OK;
		goto exit;
	}

	if (sdp_parse_session_level_attr(sdp, &line, &len, &session->a,
			parse_attr_specific) == SDP_PARSE_ERROR) {
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

		/* add media to session */
		for (next = &session->media; *next; next = &(*next)->next);
		if (!(*next= (struct sdp_media*)calloc(1,
                		sizeof(struct sdp_media)))) {
			goto exit;
                }

		media = *next;

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
		if (sdp_parse_media_level_attr(sdp, &line, &len, &media->a,
				parse_attr_specific) == SDP_PARSE_ERROR) {
			goto exit;
		}
	} while (line && !is_line_delim(*line));

	err = SDP_PARSE_OK;
	goto exit;

exit:
	free(line);
	return err;
}

static void sdpout(char *level, char *fmt, va_list va)
{
	fprintf(stderr, "SDP parse %s - ", level);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	fflush(stderr);
}

SDPOUT(warn, "warning")
SDPOUT(err, "error")

static struct sdp_media *sdp_media_locate(struct sdp_media *media,
		enum sdp_media_type type)
{
	if (type == SDP_MEDIA_TYPE_NONE)
		return media;

	for ( ; media && media->m.type != type; media = media->next);
	return media;
}

struct sdp_media *sdp_media_get(struct sdp_session *session,
		enum sdp_media_type type)
{
	return sdp_media_locate(session->media, type);
}

struct sdp_media *sdp_media_get_next(struct sdp_media *media)
{
	return sdp_media_locate(media->next, media->m.type);
}

static struct sdp_attr *sdp_attr_locate(struct sdp_attr *attr,
		enum sdp_attr_type type)
{
	if (attr && attr->type == SDP_ATTR_NONE)
		return attr;

	for ( ; attr && attr->type != type; attr = attr->next);
	return attr;
}

struct sdp_attr *sdp_media_attr_get(struct sdp_media *media,
		enum sdp_attr_type type)
{
	return sdp_attr_locate(media->a, type);
}

struct sdp_attr *sdp_session_attr_get(struct sdp_session *session,
		enum sdp_attr_type type)
{
	return sdp_attr_locate(session->a, type);
}

struct sdp_attr *sdp_attr_get_next(struct sdp_attr *attr)
{
	return sdp_attr_locate(attr->next, attr->type);
}

