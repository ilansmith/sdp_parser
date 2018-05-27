#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#if defined(__linux__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#elif defined(_WIN32)
#include <Winsock2.h>
#else
#error non supported platform
#endif

#include "util.h"
#include "sdp_parser.h"
#include "sdp_field.h"

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

#define IS_WHITESPACE_DELIM(_c_) ((_c_) == ' ' || (_c_) == '\t'|| \
	(_c_) == '\r' || (_c_) == '\n')

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

static void sdpout(char *level, char *fmt, va_list va)
{
	fprintf(stderr, "SDP parse %s - ", level);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	fflush(stderr);
}

SDPOUT(warn, "warning")
SDPOUT(err, "error")

enum sdp_parse_err sdprerr(char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	sdpout("error", fmt, va);
	va_end(va);
	return SDP_PARSE_ERROR;
}

/* returns an SDP line with no trailing whitespaces or line delimiters */
static size_t sdp_getline(char **line, size_t *len, sdp_stream_t sdp)
{
	ssize_t ret;

	ret = sdp_stream_getline(line, len, sdp);
	if (ret <= 0) {
		free(*line);
		*line = NULL;
		*len = 0;
		return 0;
	}

	while (ret && IS_WHITESPACE_DELIM((*line)[ret-1]))
		ret--;
	(*line)[ret] = 0;

	if (!ret) {
		free(*line);
		*line = NULL;
		*len = 0;
		return 0;
	}

	return ret;
}

static char sdp_parse_descriptor_type(char *line)
{
	char descriptor;

	if (strlen(line) < 3) {
		sdperr("'x=<token>' format not found");
		return 0;
	}
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

		sdp_getline(line, len, sdp);
	} while (*line);

	return SDP_PARSE_NOT_SUPPORTED;
}

static enum sdp_parse_err sdp_parse_version(sdp_stream_t sdp, char **line,
		size_t *len, struct sdp_session_v *v)
{
	int version;
	char *ptr;
	char *endptr;

	if (!sdp_getline(line, len, sdp)||
			sdp_parse_descriptor_type(*line) != 'v')
		return sdprerr("missing required sdp version");

	ptr = *line + 2;
	version = strtol(ptr, &endptr, 10);
	if (*endptr)
		return sdprerr("bad version - %s", *line);

	v->version = version;

	if (!sdp_getline(line, len, sdp))
		return sdprerr("no more sdp fields after version");

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_session_name(sdp_stream_t sdp, char **line,
		size_t *len, char **s)
{
	char *ptr;

	if (strncmp(*line, "s=", 2)) {
		sdperr("missing required sdp session name");
		return SDP_PARSE_ERROR;
	}

	ptr = *line + 2;
	if (!*ptr) {
		sdperr("sdp session name cannot remain empty");
		return SDP_PARSE_ERROR;
	}

	*s = strdup(ptr);
	if (!*s) {
		sdperr("memory acllocation");
		return SDP_PARSE_ERROR;
	}

	if (!sdp_getline(line, len, sdp)) {
		sdperr("no more sdp fields after session name");
		free(*s);
		*s = NULL;

		return SDP_PARSE_ERROR;
	}

	return SDP_PARSE_OK;
}

static int is_multicast_addr(enum sdp_ci_addrtype addrtype, char *addr)
{
	switch (addrtype) {
	case SDP_CI_ADDRTYPE_IPV4:
		return ((unsigned long)inet_addr(addr) & htonl(0xf0000000)) ==
			htonl(0xe0000000); /* 224.0.0.0 - 239.255.255.255 */
	case SDP_CI_ADDRTYPE_IPV6:
		/* not supported */
	default:
		break;
	}

	return 0;
}

static enum sdp_parse_err sdp_parse_connection_information(sdp_stream_t sdp,
		char **line, size_t *len, struct sdp_connection_information *c)
{
	char *nettype;
	char *addrtype;
	char *addr;
	char *ptr;
	char *tmp;
	int ttl = 0;
	int is_ttl_set = 0;

	if (strncmp(*line, "c=", 2))
		return SDP_PARSE_OK;

	ptr = *line + 2;
	nettype = strtok_r(ptr, " ", &tmp);
	if (!nettype)
		return sdprerr("bad connection information nettype");

	addrtype = strtok_r(NULL, " ", &tmp);
	if (!addrtype)
		return sdprerr("bad connection information addrtype");

	addr = strtok_r(NULL, "/", &tmp);
	if (!addr) {
		addr = tmp;
	} else {
		char *endptr;

		ttl = strtol(tmp, &endptr, 10);
		if (*endptr)
			return sdprerr("bad connection information ttl");

		if (ttl)
			is_ttl_set = 1;
	}

	if (!strncmp(nettype, "IN", strlen("IN")))
		c->nettype = SDP_CI_NETTYPE_IN;
	else
		c->nettype = SDP_CI_NETTYPE_NOT_SUPPORTED;

	if (!strncmp(addrtype, "IP4", strlen("IP4"))) {
		if (!is_ttl_set && is_multicast_addr(SDP_CI_ADDRTYPE_IPV4, addr))
			return sdprerr("connection information with an IP4 multicast "
				"address requires a TTL value");

		c->addrtype = SDP_CI_ADDRTYPE_IPV4;
	} else if (!strncmp(nettype, "IP6", strlen("IP6"))) {
		c->addrtype = SDP_CI_ADDRTYPE_IPV6;
	} else {
		c->addrtype = SDP_CI_ADDRTYPE_NOT_SUPPORTED;
	}

	strncpy(c->sdp_ci_addr, addr, sizeof(c->sdp_ci_addr));
	c->sdp_ci_ttl = ttl;
	c->count = 1;

	sdp_getline(line, len, sdp);
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_media_properties(struct sdp_media_m *m,
		char **tmp)
{
	char *proto;
	int port;
	int num_ports;
	int fmt;
	char *slash;
	char *endptr;
	struct sdp_media_fmt **smf;

	slash = strchr(*tmp, '/');
	port = strtol(strtok_r(NULL, " /", tmp), &endptr, 10);
	if (*endptr)
		return sdprerr("bad media descriptor - port");

	if (slash + 1 == *tmp) {
		num_ports = strtol(strtok_r(NULL, " ", tmp), &endptr, 10);
		if (*endptr)
			return sdprerr("bad media descriptor - num_ports");
	} else {
		num_ports = 1;
	}

	proto = strtok_r(NULL, " ", tmp);
	fmt = strtol(strtok_r(NULL, " ", tmp), &endptr, 10);
	if (*endptr)
		return sdprerr("bad media descriptor - fmt");

	if (!strncmp(proto, "RTP/AVP", strlen("RTP/AVP"))) {
		m->proto = SDP_MEDIA_PROTO_RTP_AVP;
	} else {
		sdperr("media protocol not supported: %s", proto);
		m->proto = SDP_MEDIA_PROTO_NOT_SUPPORTED;
		return SDP_PARSE_NOT_SUPPORTED;
	}

	m->port = port;
	m->num_ports = num_ports;
	m->fmt.id = fmt;

	smf = &m->fmt.next;
	while (*tmp && **tmp) {
		if (!(*smf = (struct sdp_media_fmt*)calloc(1,
				sizeof(struct sdp_media_fmt))))
			return sdprerr("memory acllocation");

		fmt = strtol(strtok_r(NULL, " ", tmp), &endptr, 10);
		if (*endptr)
			return sdprerr("bad media descriptor - fmt");
		(*smf)->id = fmt;
		smf = &(*smf)->next;
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_media(sdp_stream_t sdp, char **line,
		size_t *len, struct sdp_media_m *m)
{
	char *type;
	char *ptr;
	char *tmp;
	enum sdp_parse_err err;

	if (strncmp(*line, "m=", 2))
		return sdprerr("bad media descriptor - m=");

	ptr = *line + 2;
	type = strtok_r(ptr, " ", &tmp);
	if (!type)
		return sdprerr("bad media descriptor");

	/* Parse media type: */
	if (!strncmp(type, "video", strlen("video"))) {
		m->type = SDP_MEDIA_TYPE_VIDEO;
	} else if (!strncmp(type, "audio", strlen("audio"))) {
		m->type = SDP_MEDIA_TYPE_AUDIO;
	} else {
		m->type = SDP_MEDIA_TYPE_NOT_SUPPORTED;
	}

	if (m->type == SDP_MEDIA_TYPE_NOT_SUPPORTED) {
		sdpwarn("media type not supported: %s", type);
		err = SDP_PARSE_NOT_SUPPORTED;
	} else {
		err = sdp_parse_media_properties(m, &tmp);
	}

	sdp_getline(line, len, sdp);
	return err;
}

static enum sdp_parse_err parse_attr_common(struct sdp_attr *a, char *attr,
		char *value, char *params, struct sdp_specific *specific)
{
	NOT_IN_USE(a);
	NOT_IN_USE(attr);
	NOT_IN_USE(value);
	NOT_IN_USE(params);
	NOT_IN_USE(specific);

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_attr(sdp_stream_t sdp, char **line,
		size_t *len, struct sdp_media *media, struct sdp_attr **a,
		char **attr_level,
		enum sdp_parse_err (*parse_level)(struct sdp_media *media,
			struct sdp_attr *a, char *attr, char *value,
			char *params, struct sdp_specific *specific),
		struct sdp_specific *specific)
{
	char **supported_attr;
	char *attr;
	char *value;
	char *params;
	enum sdp_parse_err err;
	char *ptr = *line;
	char *tmp = NULL;

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

	while (*line && sdp_parse_descriptor_type(*line) == 'a') {
		value = NULL;
		params = NULL;
		ptr = *line + 2;

		attr = strtok_r(ptr, ":", &tmp);
		if (attr)
			value = strtok_r(NULL, " ", &tmp);
		if (value)
			params = strtok_r(NULL, "", &tmp);

		*a = (struct sdp_attr*)calloc(1, sizeof(struct sdp_attr));
		if (!*a)
			return sdprerr("memory acllocation");

		/* try to find a supported attribute in the session/media
		 * common list */
		for (supported_attr = common_level_attr; *supported_attr &&
			strcmp(*supported_attr, attr); supported_attr++);
		if (*supported_attr) {
			err = parse_attr_common(*a, *supported_attr, value, params,
					specific);
			if (err == SDP_PARSE_ERROR) {
				free(*a);
				*a = NULL;
				return sdprerr("parsing attribute: %s", attr);
			}

			a = &(*a)->next;

			sdp_getline(line, len, sdp);
			continue;
		}

		/* try to find supported attribute in current level list */
		for (supported_attr = attr_level; *supported_attr &&
			strcmp(*supported_attr, attr); supported_attr++);
		if (*supported_attr) {
			err = parse_level(media, *a, *supported_attr, value, params,
					specific);
			if (err == SDP_PARSE_ERROR) {
				free(*a);
				*a = NULL;
				return sdprerr("parsing attribute: %s", attr);
			}

			a = &(*a)->next;

			sdp_getline(line, len, sdp);
			continue;
		}

		/* attribute is not supported */
		free(*a);
		*a = NULL;

		sdp_getline(line, len, sdp);
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err parse_attr_session(struct sdp_media *media,
		struct sdp_attr *a, char *attr, char *value, char *params,
		struct sdp_specific *specific)
{
	if (!strncmp(attr, "group", strlen("group"))) {
		/* currently not supporting the general case */
		sdp_attribute_interpreter interpreter =
			specific->group;

		if (!interpreter)
			return SDP_PARSE_NOT_SUPPORTED;

		return interpreter(media, a, value, params);
	} else {
		a->type = SDP_ATTR_NOT_SUPPORTED;
		return SDP_PARSE_NOT_SUPPORTED;
	}

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_session_level_attr(sdp_stream_t sdp,
		char **line, size_t *len, struct sdp_attr **a,
		struct sdp_specific *specific)
{
	static char *session_level_attr[] = {
		"group",
		NULL
	};

	return sdp_parse_attr(sdp, line, len, NULL, a, session_level_attr,
		parse_attr_session, specific);
}

static int sdp_parse_fmt(struct sdp_media *media,
		struct sdp_media_fmt **field, char *value)
{
	int fmt_id;
	struct sdp_media_fmt *fmt;

	if (sdp_parse_int(&fmt_id, value) != SDP_PARSE_OK)
		return 0;

	for (fmt = &media->m.fmt; fmt; fmt = fmt->next) {
		if (fmt->id == fmt_id) {
			*field = fmt;
			return 1;
		}
	}
	sdperr("media format not found: %u. Media formats are listed in m=\n",
		fmt_id);
	return 0;
}

static enum sdp_parse_err sdp_parse_attr_source_filter(struct sdp_media *media,
		struct sdp_attr *attr, char *value, char *params,
		struct sdp_specific *specific)
{
	struct sdp_attr_value_source_filter *source_filter =
			&attr->value.source_filter;
	char *nettype;
	char *addrtype;
	char *dst_addr;
	char *src_addr;
	char *tmp;
	struct source_filter_src_addr src_list;
	int src_list_len;

	NOT_IN_USE(media);
	NOT_IN_USE(specific);

	/* filter-mode */
	if (!strncmp(value, "incl", strlen("incl")))
		source_filter->mode = SDP_ATTR_SRC_FLT_INCL;
	else if (!strncmp(value, "excl", strlen("excl")))
		source_filter->mode = SDP_ATTR_SRC_FLT_EXCL;
	else
		return sdprerr("bad source-filter mode type");

	/* filter-spec */
	nettype = strtok_r(params, " ", &tmp);
	if (!nettype)
		return sdprerr("bad source-filter nettype");

	addrtype = strtok_r(NULL, " ", &tmp);
	if (!addrtype)
		return sdprerr("bad source-filter addrtype");

	dst_addr = strtok_r(NULL, " ", &tmp);
	if (!dst_addr)
		return sdprerr("bad source-filter dst-addr");

	src_addr = strtok_r(NULL, " ", &tmp);
	if (!src_addr)
		return sdprerr("bad source-filter src-addr");

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

static enum sdp_parse_err parse_attr_rtpmap(struct sdp_media *media,
		struct sdp_attr *attr, char *value, char *params,
		struct sdp_specific *specific)
{
	struct sdp_attr_value_rtpmap *rtpmap = &attr->value.rtpmap;
	char *encoding_name, *clock_rate, *encoding_parameters;
	char *tmp = NULL;

	encoding_name = params ? strtok_r(params, "/", &tmp) : NULL;
	if (!encoding_name)
		return sdprerr("missing required field - encoding-name");

	clock_rate = strtok_r(NULL, "/", &tmp);
	if (!clock_rate)
		return sdprerr("missing required field - clock-rate");

	encoding_parameters = strtok_r(NULL, "", &tmp);

	/* parse fields */
	if (!sdp_parse_fmt(media, &rtpmap->fmt, value))
		return sdprerr("parsing field: payload_type");

	if (sdp_parse_field(media, attr, &rtpmap->encoding_name, encoding_name,
			specific->rtpmap_encoding_name) != SDP_PARSE_OK)
		return sdprerr("parsing field: encoding_name");
	if (sdp_parse_int(&rtpmap->clock_rate, clock_rate) != SDP_PARSE_OK)
		return sdprerr("parsing field: clock_rate");
	if (sdp_parse_field(media, attr, &rtpmap->encoding_parameters,
			encoding_parameters, specific->rtpmap_encoding_parameters)
			!= SDP_PARSE_OK)
		return sdprerr("parsing field: encoding_parameters");
	if (rtpmap->clock_rate == 0)
		return sdprerr("invalid clock-rate: %s", clock_rate);
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_attr_ptime(struct sdp_media *media,
		struct sdp_attr *attr, char *value, char *params,
		struct sdp_specific *specific)
{
	struct sdp_attr_value_ptime *ptime = &attr->value.ptime;
	NOT_IN_USE(media);
	NOT_IN_USE(params);
	NOT_IN_USE(specific);

	if (sdp_parse_float(&ptime->packet_time, value) != SDP_PARSE_OK)
		return SDP_PARSE_ERROR;
	if (ptime->packet_time == 0.0)
		return sdprerr("invalid packet-time: %s", value);
	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_attr_fmtp(struct sdp_media *media,
		struct sdp_attr *attr, char *value, char *params,
		struct sdp_specific *specific)
{
	struct sdp_attr_value_fmtp *fmtp = &attr->value.fmtp;
	if (!sdp_parse_fmt(media, &fmtp->fmt, value))
		return sdprerr("parsing field: format");

	return sdp_parse_field(media, attr, &fmtp->params, params,
			specific->fmtp_params);
}

static enum sdp_parse_err sdp_parse_attr_mid(struct sdp_media *media,
		struct sdp_attr *attr, char *value, char *params,
		struct sdp_specific *specific)
{
	struct sdp_attr_value_mid *mid = &attr->value.mid;
	NOT_IN_USE(media);
	NOT_IN_USE(params);
	NOT_IN_USE(specific);

	if (sdp_parse_str(&mid->identification_tag, value) != SDP_PARSE_OK)
		return sdprerr("parsing field: identification_tag");

	if (media->mid) {
		return sdprerr("media cannot have more than one mid field. "
			"Previous was: '%s'. Current: '%s'",
			media->mid->identification_tag, value);
	}
	media->mid = mid;

	return SDP_PARSE_OK;
}

static enum sdp_parse_err sdp_parse_attr_framerate(struct sdp_media *media,
		struct sdp_attr *attr, char *value, char *params,
		struct sdp_specific *specific)
{
	struct sdp_attr_value_framerate *framerate = &attr->value.framerate;
	NOT_IN_USE(media);
	NOT_IN_USE(params);
	NOT_IN_USE(specific);

	if (sdp_parse_double(&framerate->frame_rate, value) != SDP_PARSE_OK)
		return sdprerr("parsing field: frame_rate");
	if (framerate->frame_rate == 0.0)
		return sdprerr("invalid frame_rate: %s", value);
	return SDP_PARSE_OK;
}

static enum sdp_parse_err parse_attr_media(struct sdp_media *media,
		struct sdp_attr *a, char *attr, char *value, char *params,
		struct sdp_specific *specific)
{
	enum sdp_parse_err err;

	if (!strncmp(attr, "rtpmap", strlen("rtpmap"))) {
		a->type = SDP_ATTR_RTPMAP;
		err = parse_attr_rtpmap(media, a, value, params, specific);
	} else if (!strncmp(attr, "ptime", strlen("ptime"))) {
		a->type = SDP_ATTR_PTIME;
		err = sdp_parse_attr_ptime(media, a, value, params, specific);
	} else if (!strncmp(attr, "fmtp", strlen("fmtp"))) {
		a->type = SDP_ATTR_FMTP;
		err = sdp_parse_attr_fmtp(media, a, value, params, specific);
	} else if (!strncmp(attr, "source-filter", strlen("source-filter"))) {
		a->type = SDP_ATTR_SOURCE_FILTER;
		err = sdp_parse_attr_source_filter(media, a, value, params, specific);
	} else if (!strncmp(attr, "mid", strlen("mid"))) {
		a->type = SDP_ATTR_MID;
		err = sdp_parse_attr_mid(media, a, value, params, specific);
	} else if (!strncmp(attr, "framerate", strlen("framerate"))) {
		a->type = SDP_ATTR_FRAMERATE;
		err = sdp_parse_attr_framerate(media, a, value, params, specific);
	} else {
		a->type = SDP_ATTR_NOT_SUPPORTED;
		err = SDP_PARSE_NOT_SUPPORTED;
	}
	return err;
}

static enum sdp_parse_err sdp_parse_media_level_attr(sdp_stream_t sdp,
		char **line, size_t *len, struct sdp_media *media,
		struct sdp_attr **a, struct sdp_specific *specific)
{
	static char *media_level_attr[] = {
#if 0
		"maxptime",
		"orient",
		"quality",
#endif
		"framerate",
		"ptime",
		"rtpmap",
		"fmtp",
		"source-filter",
		"mid",
		NULL
	};

	return sdp_parse_attr(sdp, line, len, media, a, media_level_attr,
		parse_attr_media, specific);
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
		case SDP_ATTR_RTPMAP:
			sdp_free_field(&tmp->value.rtpmap.encoding_name);
			sdp_free_field(&tmp->value.rtpmap.encoding_parameters);
			break;
		case SDP_ATTR_FMTP:
			sdp_free_field(&tmp->value.fmtp.params);
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
		case SDP_ATTR_NOT_SUPPORTED:
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
	free(session->s);
	sdp_attr_free(session->a);
	media_free(session->media);
	free(session);
}

enum sdp_parse_err validate_media_blocks(struct sdp_session *session,
		struct sdp_specific *specific)
{
	struct sdp_media *media;
	enum sdp_parse_err err;

	for (media = session->media; media; media = media->next) {
		if (!specific->validator)
			continue;

		err = specific->validator(media);
		if (err != SDP_PARSE_OK) {
			sdperr("media validation failed for %s",
					specific->name);
			return err;
		}
	}
	return SDP_PARSE_OK;
}

enum sdp_parse_err sdp_session_parse(struct sdp_session *session,
		struct sdp_specific *specific)
{
	enum sdp_parse_err err = SDP_PARSE_ERROR;
	char *line = NULL;
	size_t len = 0;
	sdp_stream_t sdp = session->sdp;

	/* Default is no-specific */
	if (!specific)
		specific = no_specific;

	/* parse v= */
	if (sdp_parse_version(sdp, &line, &len, &session->v) ==
			SDP_PARSE_ERROR) {
		goto exit;
	}

	/* skip parsing of non supported session-level descriptors */
	if (sdp_parse_non_supported(sdp, &line, &len, "o") ==
			SDP_PARSE_ERROR) {
		goto exit;
	}

	/* parse s= */
	if (sdp_parse_session_name(sdp, &line, &len, &session->s) ==
			SDP_PARSE_ERROR) {
		goto exit;
	}

	/* skip parsing of non supported session-level descriptors */
	if (sdp_parse_non_supported(sdp, &line, &len, "iuep") ==
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

	if (sdp_parse_session_level_attr(sdp, &line, &len, &session->a, specific)
			== SDP_PARSE_ERROR) {
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
		enum sdp_parse_err err;

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
		err = sdp_parse_media(sdp, &line, &len, &media->m);
		if (err == SDP_PARSE_ERROR)
			goto exit;

		/* skip non suppored m= media blocks */
		if (err == SDP_PARSE_NOT_SUPPORTED) {
			while (line && sdp_parse_descriptor_type(line) != 'm')
				sdp_getline(&line, &len, sdp);
			continue;
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
		if (sdp_parse_media_level_attr(sdp, &line, &len, media, &media->a,
				specific) == SDP_PARSE_ERROR) {
			goto exit;
		}
	} while (line);



	if ((err = validate_media_blocks(session, specific)) != SDP_PARSE_OK)
		goto exit;
	err = SDP_PARSE_OK;
	goto exit;

exit:
	free(line);
	return err;
}

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

