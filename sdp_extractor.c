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

#define MAX_STRMS_PER_DUP 2
#define IPV4_MAX_HDR_LEN 60
#define IP_MAX_HDR_LEN IPV4_MAX_HDR_LEN

struct pgroup_info {
	int size;
	int coverage;
};

enum rm_media_type {
	RM_MEDIA_TYPE_UNKNOWN,
	RM_MEDIA_TYPE_VIDEO_2110_20,
	RM_MEDIA_TYPE_VIDEO_2022_06,
	RM_MEDIA_TYPE_AUDIO,
	RM_MEDIA_TYPE_ANCILLARY
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
	double ptime;
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
	enum rm_media_type media_type;
	union {
		struct media_attribute_video video;
		struct media_attribute_audio audio;
		struct media_attribute_ancillary anc;
	} type;
};

struct sdp_extractor {
	struct sdp_session *session;

	int stream_num;
	struct sdp_specific *parser;
	struct media_attribute attributes[MAX_STRMS_PER_DUP];
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

static struct sdp_media *find_media_block(struct sdp_extractor *e, int index)
{
	struct sdp_session *session = e->session;
	struct sdp_media *media;
	int i;

	for (media = session->media, i = 0; media; media = media->next, i++) {
		if (i == index)
			return media;
	}

	sdp_extractor_err("media block index %d exceeds the number of media "
		"blocks %d", index, i);
	return NULL;
}

static struct sdp_connection_information *get_connection_information(
		struct sdp_session *session, struct sdp_media *media) {
	if (media->c.count)
		return &media->c;

	if (session->c.count)
		return &session->c;

	return NULL;
}

static int extract_networking_info(struct sdp_extractor *e, vector_t medias)
{
	struct sdp_session *session = e->session;
	struct sdp_media **media;
	int i = 0;

	VEC_FOREACH(medias, media) {
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

	attributes[i].media_type = RM_MEDIA_TYPE_VIDEO_2110_20;
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
					&attributes[i].type.video.packet_size)) {
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

	attributes[i].media_type = RM_MEDIA_TYPE_AUDIO;
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

	attributes[i].media_type = RM_MEDIA_TYPE_ANCILLARY;
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

	attributes[i].media_type = RM_MEDIA_TYPE_VIDEO_2022_06;
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

static int extract_stream_params(struct sdp_extractor *e, vector_t medias,
		int npackets)
{
	struct sdp_session *session = e->session;
	struct sdp_media **media;
	int i = 0;

	VEC_FOREACH(medias, media) {
		int ret = 1;

		if (e->parser == smpte2110) {
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
		} else if (e->parser == smpte2022) {
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

static vector_t get_group_medias(struct sdp_media *media)
{
	vector_t result;
	
	result = vec_init(NULL);
	if (!result)
		return NULL;

	if (media->group) {
		struct group_identification_tag *tag;

		for (tag = media->group->tag; tag; tag = tag->next) {
			if (tag->media)
				vec_push_back(result, tag->media);
		}
	} else {
		vec_push_back(result, media);
	}

	return result;
}
 
static int sdp_parse(struct sdp_extractor *e, void *sdp, int media_block_index,
		enum sdp_stream_type type)
{
	struct sdp_session *session;
	static struct sdp_specific *supported_parsers[2];
	struct sdp_specific *parser;
	struct sdp_media *media;
	vector_t medias;
	int i;
	int ret;

	supported_parsers[0] = smpte2110;
	supported_parsers[1] = smpte2022;

	for (i = 0; i < ARRAY_SIZE(supported_parsers); i++) {
		session = sdp_parser_init(type, sdp);
		if (!session) {
			sdp_extractor_err("failed to initialize sdp parser");
			return -1;
		}

		parser = supported_parsers[i];
		sdp_extractor_info("trying to parse using %s...", parser->name);
		if (sdp_session_parse(session, parser) == SDP_PARSE_OK)
			break;

		sdp_parser_uninit(session);
	}

	if (i == ARRAY_SIZE(supported_parsers)) {
		sdp_extractor_err("sdp parsing failed");
		return -1;
	}

	e->session = session;
	e->parser = parser;
	sdp_extractor_info("sdp parsed successfully");

	media = find_media_block(e, media_block_index);
	if (!media)
		return -1;

	/* extract number of dup sessions */
	medias = get_group_medias(media);
	if (!medias)
		return -1;
	e->stream_num = vec_size(medias);
	if (e->stream_num < 1 || MAX_STRMS_PER_DUP < e->stream_num) {
		sdp_extractor_err("bad number of dup sessions: %d",
			e->stream_num);
		ret = -1;
		goto exit;
	}
	if (MAX_STRMS_PER_DUP < e->stream_num) {
		sdp_extractor_err("sdp extractor is limited to %d media "
			"sections", MAX_STRMS_PER_DUP);
		ret = -1;
		goto exit;
	}

	/* extract source address and destination address/port */
	if (extract_networking_info(e, medias)) {
		sdp_extractor_err("failed to parse networking info");
		ret = -1;
		goto exit;
	}

	/* extract packet size and rate */
	if (extract_stream_params(e, medias, 0)) {
		sdp_extractor_err("failed to parse stream parameters");
		ret = -1;
		goto exit;
	}

	ret = 0;

exit:
	vec_uninit(medias);
	return ret;
}

char *sdp_extractor_get_session_name(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	return e->session->s;
}

int sdp_extractor_get_stream_num(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	return e->stream_num;
}

int sdp_extractor_get_packaging_mode(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].type.video.pm;
}

char *sdp_extractor_get_src_ip(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return NULL;

	return *e->attributes[dup].addr_src ?
		e->attributes[dup].addr_src : "N/A";
}

char *sdp_extractor_get_dst_ip(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return NULL;

	return e->attributes[dup].addr_dst;
}

uint16_t sdp_extractor_get_dst_port(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].port_dst;
}

int sdp_extractor_get_packet_size(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].type.video.packet_size;
}

double sdp_extractor_get_rate(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].type.video.rate;
}

int sdp_extractor_get_is_rate_integer(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].type.video.is_rate_integer;
}

int sdp_extractor_get_npackets(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].type.video.npackets;
}

double sdp_extractor_get_fps(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].type.video.fps;
}

int sdp_extractor_get_type(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].type.video.type;
}

int sdp_extractor_get_signal(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->attributes[dup].type.video.signal;
}

int sdp_extractor_set_npackets(sdp_extractor_t sdp_extractor, int npackets,
		int media_block_index)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;
	struct sdp_media *media;
	vector_t medias;
	int ret;
	
	media = find_media_block(e, media_block_index);
	if (!media)
		return -1;

	medias = get_group_medias(media);
	ret = extract_stream_params(e, medias, npackets);
	vec_uninit(medias);
	return ret;
}

void sdp_extractor_uninit(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->session)
		sdp_parser_uninit(e->session);
	memset(e, 0, sizeof(struct sdp_extractor));
	free(e);
}

sdp_extractor_t sdp_extractor_init(void *sdp, int media_block_index,
		enum sdp_stream_type type)
{
	struct sdp_extractor *e;

	e = (struct sdp_extractor*)calloc(1, sizeof(struct sdp_extractor));
	if (!e)
		return NULL;

	if (sdp_parse(e, sdp, media_block_index, type)) {
		sdp_extractor_uninit((sdp_extractor_t)e);
		return NULL;
	}

	return (sdp_extractor_t)e;
}

