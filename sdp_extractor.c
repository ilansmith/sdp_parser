#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "sdp_parser.h"
#include "smpte2110_sdp_parser.h"
#include "sdp_extractor.h"
#include "vector.h"

#define NOT_IN_USE(a) ((void)(a))

#define SDP_EXTRACTOR_OUT(func_suffix, level) \
	void sdp_extractor_ ## func_suffix(char *fmt, ...) \
	{ \
		va_list va; \
		va_start(va, fmt); \
		sdp_extractor_out(level, fmt, va); \
		va_end(va); \
	}

#define SDP_EXTRACTOR_GET_BY_STREAM(_type_, _err_, _name_, _field_) \
_type_ sdp_extractor_get_ ## _name_ ## _by_stream( \
		sdp_extractor_t sdp_extractor, int m_idx) \
{ \
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor; \
\
	if (vec_size(e->medias) <= m_idx) \
	 	return _err_; \
\
	return e->attributes[m_idx]._field_; \
}

#define SDP_EXTRACTOR_GET_BY_GROUP(_type_, _err_, _name_, _field_) \
	_type_ sdp_extractor_get_ ## _name_ ## _by_group( \
		sdp_extractor_t sdp_extractor, int g_idx, int t_idx) \
	{ \
		struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;\
		struct group_member *member; \
		struct sdp_media **media; \
		int m_idx; \
\
		member = get_member(e, g_idx, t_idx); \
		if (!member) \
			return _err_; \
\
		m_idx = 0; \
		VEC_FOREACH(e->medias, media) { \
			if (*media == member->media) \
				return e->attributes[m_idx]._field_; \
			m_idx++; \
		} \
		return _err_; \
	}

#define SDP_EXTRACTOR_GET(_type_, _err_, _name_, _field_) \
	SDP_EXTRACTOR_GET_BY_STREAM(_type_, _err_, _name_, _field_) \
	SDP_EXTRACTOR_GET_BY_GROUP(_type_, _err_, _name_, _field_)

#define ARRAY_SIZE(_arr_) (sizeof(_arr_) / sizeof(_arr_)[0])

#define BYTE_SIZE 8
#define BPM_OCTET_MULTIPLE 180 
#define MAC_HDR_SIZE 14
#define UDP_HDR_SIZE 8
#define IPV4_HDR_SIZE 20
#define IPV6_HDR_SIZE 40
#define RTP_HDR_SIZE 12
#define RTP_EXT_SEQ_NUM 2
#define RTP_EXT_HDR_SIZE 6
#define STANDARD_UDP_SIZE_LIMIT 1460
#define STANDARD_UDP_SIZE_LIMIT_JUMBO 8960
#define FPS_NON_INT_DEMONINATOR 1001

#define IPV4_MAX_HDR_LEN 60
#define IP_MAX_HDR_LEN IPV4_MAX_HDR_LEN

struct pgroup_info {
	int size;
	int coverage;
};

struct media_attribute_video {
	int packet_size;
	double rate;
	uint16_t width;
	uint16_t height;
	enum smpte_2110_colorimetry colorimetry;
	int is_rate_integer;
	enum smpte_2110_pm pm;
	int npackets;
	double fps;
	enum smpte_2110_tp type;
	enum smpte_2110_signal signal;
};

struct media_attribute_audio {
	int bit_depth;
	int num_channels;
	int sampling_rate;
	double ptime;
	char *channel_order;
};

struct media_attribute_ancillary {
	int dummy;
};

struct media_attribute {
	char addr_src[IP_MAX_HDR_LEN + 1];
	char addr_dst[IP_MAX_HDR_LEN + 1];
	uint16_t port_dst;
	uint8_t ttl;
	uint32_t clock_rate;
	enum sdp_extractor_spec_sub_type media_type;
	union {
		struct media_attribute_video video;
		struct media_attribute_audio audio;
		struct media_attribute_ancillary anc;
	} type;
};

struct sdp_extractor {
	struct sdp_session *session;

	enum sdp_extractor_spec spec;
	vector_t groups;
	vector_t medias;
	struct media_attribute *attributes;
};

static void sdp_extractor_out(char *level, char *fmt, va_list va)
{
	fprintf(stderr, "SDP extractor %s - ", level);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	fflush(stderr);
}

SDP_EXTRACTOR_OUT(err, "error")
SDP_EXTRACTOR_OUT(info, "info")

static struct sdp_connection_information *get_connection_information(
		struct sdp_session *session, struct sdp_media *media) {
	if (media->c.count)
		return &media->c;

	if (session->c.count)
		return &session->c;

	return NULL;
}

static int extract_networking_info(struct sdp_extractor *e)
{
	struct sdp_session *session = e->session;
	struct sdp_media **media;
	int i = 0;

	VEC_FOREACH(e->medias, media) {
		struct sdp_attr *source_filter_attr;
		struct sdp_connection_information *c;

		source_filter_attr =
			sdp_media_attr_get(*media, SDP_ATTR_SOURCE_FILTER);
		if (!source_filter_attr) {
			sdp_extractor_err("bad sdp format, missing "
				"a=source-filter");
			return -1;
		}
		strncpy(e->attributes[i].addr_src,
			source_filter_attr->value.source_filter.spec.src_list.addr,
			IP_MAX_HDR_LEN);

		c = get_connection_information(session, *media);
		if (!c) {
			sdp_extractor_err("no connection information for "
				"stream %d", i);
			return -1;
		}
		if (c->addrtype != SDP_CI_ADDRTYPE_IPV4) {
			sdp_extractor_err("address type not supported: %d",
				c->addrtype);
			return -1;
		}

		strncpy(e->attributes[i].addr_dst, c->sdp_ci_addr,
			IP_MAX_HDR_LEN);
		e->attributes[i].port_dst = (*media)->m.port;
		i++;
	}

	return 0;
}

static int extract_pgroup_info(enum smpte_2110_sampling sampling,
		enum smpte_2110_depth depth, struct pgroup_info *pgi)
{
	static struct pgroup_info pgi_lookup_table[3][5] = {
		[SAMPLING_YCbCr_444] = {
			[DEPTH_8] = { .size = 3, .coverage = 1 },
			[DEPTH_10] = { .size = 15, .coverage = 4 },
			[DEPTH_12] = { .size = 9, .coverage = 2 },
			[DEPTH_16] = { .size = 6, .coverage = 1 },
			[DEPTH_16F] = { .size = 6, .coverage = 1 },
		},
		[SAMPLING_YCbCr_422] = {
			[DEPTH_8] = { .size = 4, .coverage = 2 },
			[DEPTH_10] = { .size = 5, .coverage = 2 },
			[DEPTH_12] = { .size = 6, .coverage = 2 },
			[DEPTH_16] = { .size = 8, .coverage = 2 },
			[DEPTH_16F] = { .size = 8, .coverage = 2 },
		},
		[SAMPLING_YCbCr_420] = {
			[DEPTH_8] = { .size = 6, .coverage = 4 },
			[DEPTH_10] = { .size = 15, .coverage = 8 },
			[DEPTH_12] = { .size = 9, .coverage = 4 },
			[DEPTH_16] = { .size = -1, .coverage = -1 },
			[DEPTH_16F] = { .size = -1, .coverage = -1 },
		},
	};

	if (pgi_lookup_table[sampling][depth].size == -1 ||
			pgi_lookup_table[sampling][depth].coverage == -1) {
		return -1;
	}

	pgi->size = pgi_lookup_table[sampling][depth].size;
	pgi->coverage = pgi_lookup_table[sampling][depth].coverage;
	return 0;
}

static int extract_packet_info(
		struct smpte2110_media_attr_fmtp_params *fmtp_params,
		struct sdp_connection_information *c, int *npackets,
		int *packet_size)
{
	int pg_per_packet;
	int pixels_per_packet;
	int pixels_total;
	int rtp_payload_size;
	int ip_hdr_size;
	int ret;
	struct pgroup_info pgi;

	ret = extract_pgroup_info(fmtp_params->sampling, fmtp_params->depth,
		&pgi);
	if (ret) {
		sdp_extractor_err("unsupported pixle sampling/depth "
			"combination, sampling:%d, depth:%d",
			fmtp_params->sampling, fmtp_params->depth); 
		return -1;
	}

	switch (c->addrtype) {
	case SDP_CI_ADDRTYPE_IPV4:
		ip_hdr_size = IPV4_HDR_SIZE;
		break;
	case SDP_CI_ADDRTYPE_IPV6:
		ip_hdr_size = IPV6_HDR_SIZE;
		break;
	default:
		sdp_extractor_err("unsupported address type: %d", c->addrtype);
		return -1;
	}

	pixels_total = fmtp_params->width * fmtp_params->height;

	if (fmtp_params->pm == PM_2110BPM) {
		int __npackets;

		/* SMPTE ST 2110-20 defines that:
		 *
		 *   The RTP Payload Header shall include
		 *   the Extended Sequence Number, followed by one, two, or
		 *   three Sample Row Data (SRD) Headers.
		 *
		 * So in the worst case there are 3 RTP_EXT_HDR_SIZE
		 *
		 * Playload size in BPM mode is a multiple of 180 bytes */
		rtp_payload_size = (fmtp_params->maxudp - (UDP_HDR_SIZE +
			RTP_HDR_SIZE + RTP_EXT_SEQ_NUM +
			3 * RTP_EXT_HDR_SIZE)) / BPM_OCTET_MULTIPLE;
		rtp_payload_size *= BPM_OCTET_MULTIPLE;

		pg_per_packet = rtp_payload_size / pgi.size;
		pixels_per_packet = pg_per_packet * pgi.coverage;

		__npackets = (pixels_total + (pixels_per_packet - 1)) /
			pixels_per_packet;

		if (*npackets && *npackets != __npackets) {
			sdp_extractor_err("incompatible number of packets for "
				"BPM packing mode: %d (should be: %d)",
				*npackets, __npackets);
			return -1;
		}

		*npackets = __npackets;
	} else if (fmtp_params->pm == PM_2110GPM) {
		int pg_num;

		if (!*npackets)
			return 0;

		/* Approximated Packet Size - assuming even pixel group
		 * distribution over the first (*npackets - 1) packets with
		 * the remaining pixel groups going in the last packet */

		pg_num = pixels_total / pgi.coverage;
		pg_per_packet = *npackets == 1 ?
			pg_num : pg_num / (*npackets - 1);
		rtp_payload_size = pg_per_packet * pgi.size;
	} else {
		return -1; /* should never get here */
	}

	/* We assume at least one RTP_EXT_HDR_SIZE */
	*packet_size = MAC_HDR_SIZE + UDP_HDR_SIZE + ip_hdr_size +
		RTP_HDR_SIZE +	RTP_EXT_SEQ_NUM + RTP_EXT_HDR_SIZE +
		rtp_payload_size;

	return 0;
}

static int check_required_attributes(const char *spec_name, uint32_t found,
		uint32_t required)
{
	int missing = required & ~found;
	int attr = 0;
	char msg[512];
	int len;
	int is_first = 1;

	if (!missing)
		return 0;

	len = snprintf(msg, sizeof(msg), "%s is missing some required "
		"attributes:", spec_name);
	while (missing > 0) {
		if (missing & 0x1) {
			len += snprintf(msg + len, sizeof(msg) - len,
				"%s (%d) %s", is_first ? "" : ",", attr,
				sdp_get_attr_type_name(
					(enum sdp_attr_type)attr));
			is_first = 0;
		}
		missing >>= 1;
		attr += 1;
	}

	sdp_extractor_err("%s", msg);
	return -1;
}

static int extract_2110_20_params(struct sdp_session *session,
		struct sdp_media *media, struct media_attribute *attributes,
		int i, int npackets)
{
	struct sdp_attr *attr;
	struct sdp_connection_information *c;
	uint32_t found_attributes = 0;

	c = get_connection_information(session, media);
	if (!c) {
		sdp_extractor_err("no connection information for stream %d", i);
		return -1;
	}

	attributes[i].media_type = SPEC_SUBTYPE_SMPTE_ST2110_20;
	for (attr = media->a; attr; attr = attr->next) {
		found_attributes  |= (1 << attr->type);

		if (attr->type == SDP_ATTR_FMTP) {
			struct smpte2110_media_attr_fmtp_params *fmtp_params =
				(struct smpte2110_media_attr_fmtp_params*)
				attr->value.fmtp.params.as.as_ptr;

			attributes[i].type.video.colorimetry =
				fmtp_params->colorimetry;
			attributes[i].type.video.width = fmtp_params->width;
			attributes[i].type.video.height = fmtp_params->height;
			attributes[i].type.video.pm = fmtp_params->pm;

			attributes[i].type.video.npackets = npackets;
			if (extract_packet_info(fmtp_params, c,
					&attributes[i].type.video.npackets,
					&attributes[i].type.video.packet_size)){
				attributes[i].type.video.npackets = 0;
				attributes[i].type.video.packet_size = 0;
				return -1;
			}
			attributes[i].type.video.is_rate_integer =
				fmtp_params->exactframerate.is_integer;
			attributes[i].type.video.fps =
				(double)fmtp_params->exactframerate.nominator;
			if (!attributes[i].type.video.is_rate_integer) {
				attributes[i].type.video.fps /=
					FPS_NON_INT_DEMONINATOR;
			}

			attributes[i].type.video.rate =
				attributes[i].type.video.packet_size *
				attributes[i].type.video.npackets *
				attributes[i].type.video.fps * BYTE_SIZE;
			attributes[i].type.video.type = fmtp_params->tp;
			attributes[i].type.video.signal = fmtp_params->signal;
		}
	}

	return check_required_attributes("2110_20", found_attributes,
		(1 << SDP_ATTR_FMTP));
}

static int extract_2110_30_params(struct sdp_session *session,
		struct sdp_media *media, struct media_attribute *attributes,
		int i)
{
	struct sdp_attr *attr;
	uint32_t found_attributes = 0;

	NOT_IN_USE(session);

	attributes[i].media_type = SPEC_SUBTYPE_SMPTE_ST2110_30;
	for (attr = media->a; attr; attr = attr->next) {
		found_attributes |= (1 << attr->type);

		if (attr->type == SDP_ATTR_RTPMAP) {
			attributes[i].clock_rate =
				attr->value.rtpmap.clock_rate;
			attributes[i].type.audio.bit_depth =
				attr->value.rtpmap.encoding_name.as.as_ll;
			attributes[i].type.audio.num_channels =
				attr->value.rtpmap.encoding_parameters.as.as_ll;
		} else if (attr->type == SDP_ATTR_PTIME) {
			attributes[i].type.audio.ptime =
				attr->value.ptime.packet_time;
		} else if (attr->type == SDP_ATTR_FMTP) {
			attributes[i].type.audio.channel_order =
				attr->value.fmtp.params.as.as_str;
		}
	}

	return check_required_attributes("2110_30", found_attributes,
		(1 << SDP_ATTR_PTIME));
}

static int extract_2110_40_params(struct sdp_session *session,
		struct sdp_media *media, struct media_attribute *attributes,
		int i)
{
	struct sdp_attr *attr;
	uint32_t found_attributes = 0;

	NOT_IN_USE(session);

	attributes[i].media_type = SPEC_SUBTYPE_SMPTE_ST2110_40;
	for (attr = media->a; attr; attr = attr->next) {
		found_attributes |= (1 << attr->type);

		if (attr->type == SDP_ATTR_RTPMAP) {
			attributes[i].clock_rate =
				attr->value.rtpmap.clock_rate;
		} else if (attr->type == SDP_ATTR_FMTP) {
			// TODO: DID_SDID / VPID_Code
		}
	}

	return check_required_attributes("2110_40", found_attributes, 0);
}

static int extract_2022_6_params(struct sdp_session *session,
		struct sdp_media *media, struct media_attribute *attributes,
		int i)
{
	struct sdp_attr *attr;
	uint32_t found_attributes = 0;

	NOT_IN_USE(session);

	attributes[i].media_type = SPEC_SUBTYPE_SMPTE_ST2022_6;
	for (attr = media->a; attr; attr = attr->next) {
		found_attributes |= (1 << attr->type);

		if (attr->type == SDP_ATTR_FRAMERATE) {
			attributes[i].type.video.fps =
				attr->value.framerate.frame_rate;
		}
	}

	return check_required_attributes("2022_6", found_attributes,
		(1 << SDP_ATTR_FRAMERATE));
}

static int extract_stream_params(struct sdp_extractor *e, int npackets)
{
	struct sdp_session *session = e->session;
	struct sdp_media **media;
	int i = 0;

	VEC_FOREACH(e->medias, media) {
		int ret = 1;

		if (e->spec == SPEC_SMPTE_ST2110) {
			if ((*media)->m.fmt.sub_type ==
					SMPTE_2110_SUB_TYPE_20) {
			ret = extract_2110_20_params(session, *media,
				e->attributes, i, npackets);
			} else if ((*media)->m.fmt.sub_type ==
					SMPTE_2110_SUB_TYPE_30) {
			ret = extract_2110_30_params(session, *media,
				e->attributes, i);
			} else if ((*media)->m.fmt.sub_type ==
					SMPTE_2110_SUB_TYPE_40) {
			ret = extract_2110_40_params(session, *media,
				e->attributes, i);
			}
		} else if (e->spec == SPEC_SMPTE_ST2022) {
			if ((*media)->m.fmt.sub_type == SMPTE_2022_SUB_TYPE_6) {
				ret = extract_2022_6_params(session, *media,
					e->attributes, i);
			}
		}

		if (ret == 1) {
			sdp_extractor_err("unsupported media format");
			return -1;
		}

		i++;
	}

	return 0;
}

static void vector_uninit(vector_t vector)
{
	vec_uninit(vector);
}

static int media_vector_init(struct sdp_session *session, vector_t *medias)
{
	struct sdp_media *media;

	*medias = vec_init(NULL);
	if (!*medias)
		return -1;

	for (media = session->media; media; media = media->next)
		vec_push_back(*medias, media);

	return 0;
}

static void media_vector_uninit(vector_t medias)
{
	vector_uninit(medias);
}

static int group_vector_init(struct sdp_session *session, vector_t *groups)
{
	struct sdp_attr *attr;
	vector_t tmp;

	tmp = vec_init(NULL);
	if (!tmp)
		return -1;

	for (attr = sdp_session_attr_get(session, SDP_ATTR_GROUP); attr;
			attr = sdp_attr_get_next(attr)) {
		vec_push_back(tmp, &attr->value.group);
	}

	*groups = tmp;
	return 0;
}

static void group_vector_uninit(vector_t groups)
{
	vector_uninit(groups);
}

static int sdp_parse(struct sdp_extractor *e, void *sdp,
		enum sdp_stream_type type)
{
	struct sdp_session *session;
	int i;
	int ret;
	static struct {
		enum sdp_extractor_spec spec;
		struct sdp_specific **parser;
	} supported_parsers[2] = {
		{ .spec = SPEC_SMPTE_ST2022, .parser = &smpte2022 },
		{ .spec = SPEC_SMPTE_ST2110, .parser = &smpte2110 },
	};

	e->spec = SPEC_UNKNOWN;
	for (i = 0; i < ARRAY_SIZE(supported_parsers); i++) {
		session = sdp_parser_init(type, sdp);
		if (!session) {
			sdp_extractor_err("failed to initialize sdp parser");
			return -1;
		}

		if (sdp_session_parse(session, *supported_parsers[i].parser) ==
				SDP_PARSE_OK) {
			e->spec = supported_parsers[i].spec;
			break;
		}

		sdp_parser_uninit(session);
	}

	if (i == ARRAY_SIZE(supported_parsers)) {
		sdp_extractor_err("sdp parsing failed");
		return -1;
	}

	e->session = session;

	ret = media_vector_init(session, &e->medias);
	if (ret) {
		sdp_extractor_err("failed to initialize medias vector");
		goto fail;
	}
	if (!vec_size(e->medias)) {
		sdp_extractor_err("no media blocks found");
		goto fail;
	}

	ret = group_vector_init(session, &e->groups);
	if (ret) {
		sdp_extractor_err("failed to initialize medias vector");
		goto fail;
	}

	e->attributes = calloc(vec_size(e->medias),
		sizeof(struct media_attribute));
	if (!e->attributes) {
		sdp_extractor_err("failed to allocate extractor attributes");
		goto fail;
	}

	/* extract source address and destination address/port */
	if (extract_networking_info(e)) {
		sdp_extractor_err("failed to parse networking info");
		goto fail;
	}

	/* extract packet size and rate */
	if (extract_stream_params(e, 0)) {
		sdp_extractor_err("failed to parse stream parameters");
		goto fail;
	}

	return 0;

fail:
	vec_uninit(e->medias);
	vec_uninit(e->groups);
	free(e->attributes);
	return -1;
}

static struct group_member *get_member(struct sdp_extractor *e, int g_idx,
		int t_idx)
{
	struct sdp_attr_value_group *group;
	struct group_member *member;

	if (vec_size(e->groups) <= g_idx)
		return NULL;

	group = (struct sdp_attr_value_group*)vec_at(e->groups, g_idx);
	if (group->num_tags <= t_idx)
		return NULL;

	for (member = group->member; t_idx; member = member->next, t_idx--);
	return member;
}

/* API implementation - spec agnostic functions */
void sdp_extractor_uninit(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	group_vector_uninit(e->groups);
	media_vector_uninit(e->medias);
	free(e->attributes);
	if (e->session)
		sdp_parser_uninit(e->session);
	memset(e, 0, sizeof(struct sdp_extractor));
	free(e);
}

sdp_extractor_t sdp_extractor_init(void *sdp, enum sdp_stream_type type)
{
	struct sdp_extractor *e;

	e = (struct sdp_extractor*)calloc(1, sizeof(struct sdp_extractor));
	if (!e)
		return NULL;

	if (sdp_parse(e, sdp, type)) {
		sdp_extractor_uninit((sdp_extractor_t)e);
		return NULL;
	}

	return (sdp_extractor_t)e;
}

enum sdp_extractor_spec sdp_extractor_get_spec(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	return e->spec;
}

char *sdp_extractor_get_session_name(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	return e->session->s;
}

int sdp_extractor_get_stream_num(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	return (int)vec_size(e->medias);
}

int sdp_extractor_get_group_num(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	return (int)vec_size(e->groups);
}

char *sdp_extractor_get_group_semantic(sdp_extractor_t sdp_extractor, int g_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;
	struct sdp_attr_value_group *group;

	if (vec_size(e->groups) <= g_idx)
		return NULL;

	group = (struct sdp_attr_value_group*)vec_at(e->groups, g_idx);
	return group->semantic;
}

int sdp_extractor_get_group_tag_num(sdp_extractor_t sdp_extractor, int g_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;
	struct sdp_attr_value_group *group;

	if (vec_size(e->groups) <= g_idx)
		return -1;

	group = (struct sdp_attr_value_group*)vec_at(e->groups, g_idx);
	return group->num_tags;
}

char *sdp_extractor_get_group_tag(sdp_extractor_t sdp_extractor,
		int g_idx, int t_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;
	struct group_member *member;

	member = get_member(e, g_idx, t_idx);
	if (!member)
		return NULL;

	return member->identification_tag;
}

char *sdp_extractor_stream_to_tag(sdp_extractor_t sdp_extractor, int m_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;
	struct sdp_media *media;

	media = vec_at(e->medias, m_idx);
	if (!media || !media->mid)
		return NULL;

	return media->mid->identification_tag;
}

enum sdp_extractor_spec_sub_type sdp_extractor_stream_sub_type(
	sdp_extractor_t sdp_extractor, int m_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (vec_size(e->medias) <= m_idx)
		return SPEC_SUBTYPE_SUBTYPE_UNKNOWN;

	return e->attributes[m_idx].media_type;
}

int sdp_extractor_get_group_index_by_stream(sdp_extractor_t sdp_extractor,
		int m_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;
	struct sdp_media *media;
	struct sdp_attr_value_group **group;
	int g_idx;

	if (vec_size(e->medias) <= m_idx)
		return -1;

	media = (struct sdp_media*)vec_at(e->medias, m_idx);
	if (!media->group)
		return -1;

	g_idx = 0;
	VEC_FOREACH(e->groups, group) {
		if (media->group == *group)
			break;
		g_idx++;
	}

	if (g_idx == vec_size(e->groups))
		return -1;

	return g_idx;
}

SDP_EXTRACTOR_GET(char *, NULL,  src_ip, addr_src)
SDP_EXTRACTOR_GET(char *, NULL,  dst_ip, addr_dst)
SDP_EXTRACTOR_GET(uint16_t, -1,  dst_port, port_dst)
static SDP_EXTRACTOR_GET(double, -1,  fps, type.video.fps)

/* API implementation - SMPTE ST2022-06 functions */
double sdp_extractor_get_2022_06_fps_by_stream(sdp_extractor_t sdp_extractor,
		int m_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->spec != SPEC_SMPTE_ST2022)
		return -1;

	return sdp_extractor_get_fps_by_stream(e, m_idx);
}

double sdp_extractor_get_2022_06_fps_by_group(sdp_extractor_t sdp_extractor,
		int g_idx, int t_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->spec != SPEC_SMPTE_ST2022)
		return -1;

	return sdp_extractor_get_fps_by_group(e, g_idx, t_idx);
}

/* API implementation - SMPTE ST2110-20 functions */
SDP_EXTRACTOR_GET(int, -1, 2110_20_packaging_mode, type.video.pm)
SDP_EXTRACTOR_GET(int, -1, 2110_20_packet_size, type.video.packet_size)
SDP_EXTRACTOR_GET(double, -1, 2110_20_rate, type.video.rate)
SDP_EXTRACTOR_GET(int, -1, 2110_20_is_rate_integer, type.video.is_rate_integer)
SDP_EXTRACTOR_GET(int, -1, 2110_20_npackets, type.video.npackets)
SDP_EXTRACTOR_GET(int, -1, 2110_20_type, type.video.type)
SDP_EXTRACTOR_GET(int, -1, 2110_20_signal, type.video.signal)
SDP_EXTRACTOR_GET(int, -1, 2110_20_width, type.video.width)
SDP_EXTRACTOR_GET(int, -1, 2110_20_height, type.video.height)

double sdp_extractor_get_2110_20_fps_by_stream(sdp_extractor_t sdp_extractor,
		int m_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->spec != SPEC_SMPTE_ST2110)
		return -1;

	return sdp_extractor_get_fps_by_stream(e, m_idx);
}

double sdp_extractor_get_2110_20_fps_by_group(sdp_extractor_t sdp_extractor,
		int g_idx, int t_idx)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->spec != SPEC_SMPTE_ST2110)
		return -1;

	return sdp_extractor_get_fps_by_group(e, g_idx, t_idx);
}

int sdp_extractor_set_2110_20_npackets(sdp_extractor_t sdp_extractor,
		int npackets)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	return extract_stream_params(e, npackets);
}

/* API implementation - SMPTE ST2110-30 functions */
SDP_EXTRACTOR_GET(int, -1, 2110_30_bit_depth, type.audio.bit_depth)
SDP_EXTRACTOR_GET(uint32_t, (uint32_t)-1, 2110_30_sampling_rate, clock_rate)
SDP_EXTRACTOR_GET(int, -1, 2110_30_num_channels, type.audio.num_channels)
SDP_EXTRACTOR_GET(char*, NULL, 2110_30_channel_order, type.audio.channel_order)
SDP_EXTRACTOR_GET(double, -1, 2110_30_ptime, type.audio.ptime)

/* API implementation - SMPTE ST2110-40 functions */
SDP_EXTRACTOR_GET(int, -1, 2110_40_dummy, type.anc.dummy)

