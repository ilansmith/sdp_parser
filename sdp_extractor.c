#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "sdp_parser.h"
#include "smpte2110_sdp_parser.h"
#include "sdp_extractor.h"

#define NOT_IN_USE(a) ((void)(a))

#define SDP_EXTRACTOR_OUT(func_suffix, level) \
	void sdp_extractor_ ## func_suffix(char *fmt, ...) \
	{ \
		va_list va; \
		va_start(va, fmt); \
		sdp_extractor_out(level, fmt, va); \
		va_end(va); \
	}

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

#define MAX_STRMS_PER_RING 2
#define IPV4_MAX_HDR_LEN 60
#define IP_MAX_HDR_LEN IPV4_MAX_HDR_LEN

struct pgroup_info {
	int size;
	int coverage;
};

struct sdp_extractor {
	struct sdp_session *session;

	int stream_num;
	enum smpte_2110_pm pm[MAX_STRMS_PER_RING];
	char addr_src[MAX_STRMS_PER_RING][IP_MAX_HDR_LEN + 1];
	char addr_dst[MAX_STRMS_PER_RING][IP_MAX_HDR_LEN + 1];
	uint16_t port_dst[MAX_STRMS_PER_RING];

	int packet_size[MAX_STRMS_PER_RING];
	double rate[MAX_STRMS_PER_RING]; /* Bytes per second */
	int is_rate_integer[MAX_STRMS_PER_RING];
	int npackets[MAX_STRMS_PER_RING];
	double fps[MAX_STRMS_PER_RING];

	enum smpte_2110_tp type[MAX_STRMS_PER_RING];
	enum smpte_2110_signal signal[MAX_STRMS_PER_RING];
};

static void sdp_extractor_out(char *level, char *fmt, va_list va)
{
	fprintf(stderr, "SDP extractor %s - ", level);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	fflush(stderr);
}

SDP_EXTRACTOR_OUT(err, "error")

static struct smpte2110_media_attr_fmtp_params *extract_fmtp_attr_params(
		struct sdp_session *session, struct sdp_media **media)
{
	struct sdp_attr *fmtp_attr;
	struct sdp_attr_value_fmtp *fmtp_value;

	*media = *media ? sdp_media_get_next(*media) :
		sdp_media_get(session, SDP_MEDIA_TYPE_VIDEO);

	if (!*media)
		return NULL;

	fmtp_attr = sdp_media_attr_get(*media, SDP_ATTR_FMTP);
	if (!fmtp_attr) {
		sdp_extractor_err("no a=fmtp found for video media");
		return NULL;
	}

	fmtp_value = &fmtp_attr->value.fmtp;
	return (struct smpte2110_media_attr_fmtp_params*)fmtp_value->params;
}

static int extract_dup_num(struct sdp_extractor *e)
{
	struct sdp_session *session = e->session;
	struct sdp_media *media;
	struct sdp_attr *group_attr;
	int dup_num = 0;
	int count_m = 0;

	/* query for a=group:DUP primary secondary */
	group_attr = sdp_session_attr_get(session, SDP_ATTR_GROUP);
	if (group_attr)
		dup_num = group_attr->value.group.num_tags;

	/* count m= blocks */
	for (media = sdp_media_get(session, SDP_MEDIA_TYPE_VIDEO);
			media; media = sdp_media_get_next(media)) {
		count_m++;
	}

	/* assert that number of m= blocks is equals dup_num */
	if (dup_num && count_m != dup_num) {
		sdp_extractor_err("bad sdp format, dup num:%d, m= count:%d",
			dup_num, count_m);

		return 0;
	}

	return count_m;
}

static int extract_pm(struct sdp_extractor *e)
{
	struct sdp_media *media = NULL;
	struct smpte2110_media_attr_fmtp_params *fmtp_params;
	int i = 0;

	while ((fmtp_params = extract_fmtp_attr_params(e->session, &media)))
		e->pm[i++] = fmtp_params->pm;

	return i == e->stream_num ? 0 : -1;
}

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
	struct sdp_media *media;
	int i;

	for (media = sdp_media_get(session, SDP_MEDIA_TYPE_VIDEO), i = 0;
			media; media = sdp_media_get_next(media), i++) {
		struct sdp_attr *source_filter_attr;
		struct sdp_connection_information *c;

		source_filter_attr =
			sdp_media_attr_get(media, SDP_ATTR_SOURCE_FILTER);
		if (source_filter_attr) {
			strncpy(e->addr_src[i],
				source_filter_attr->value.source_filter.spec.src_list.addr,
				IP_MAX_HDR_LEN);
		}

		c = get_connection_information(session, media);
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

		strncpy(e->addr_dst[i], c->sdp_ci_addr, IP_MAX_HDR_LEN);
		e->port_dst[i] = media->m.port;
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

static int extract_stream_params(struct sdp_extractor *e, int npackets)
{
	struct sdp_session *session = e->session;
	struct sdp_media *media = NULL;
	struct smpte2110_media_attr_fmtp_params *fmtp_params;
	int i = 0;

	while ((fmtp_params = extract_fmtp_attr_params(e->session, &media))) {
		struct sdp_connection_information *c;

		c = get_connection_information(session, media);
		if (!c) {
			sdp_extractor_err("no connection information for "
				"stream %d", i);
			return -1;
		}

		e->npackets[i] = npackets;
		if (extract_packet_info(fmtp_params, c, &e->npackets[i],
				&e->packet_size[i])) {
			e->npackets[i] = 0;
			e->packet_size[i] = 0;
			return -1;
		}
		e->fps[i] = (double)fmtp_params->exactframerate.nominator;
		if (!fmtp_params->exactframerate.is_integer) {
			e->fps[i] /= FPS_NON_INT_DEMONINATOR;
			e->is_rate_integer[i] = 0;
		} else {
			e->is_rate_integer[i] = 1;
		}

		e->rate[i] = e->packet_size[i] * e->npackets[i] * e->fps[i] *
			BYTE_SIZE;
		e->type[i] = fmtp_params->tp;
		e->signal[i] = fmtp_params->signal;
		i++;
	}

	return i == e->stream_num ? 0 : -1;
}

static int sdp_parse(struct sdp_extractor *e, void *sdp,
		enum sdp_stream_type type)
{
	enum sdp_parse_err err;

	e->session = sdp_parser_init(type, sdp);
	if (!e->session) {
		sdp_extractor_err("failed to parse sdp session");
		return -1;
	}

	err = sdp_session_parse(e->session, smpte2110_sdp_parse_specific);
	if (err != SDP_PARSE_OK) {
		sdp_extractor_err("sdp parsing failed");
		return -1;
	}

	/* extract number of dup sessions */
	e->stream_num = extract_dup_num(e);
	if (e->stream_num < 1) {
		sdp_extractor_err("no video streams found",
			e->stream_num);
		return -1;
	}

	/* extract packaging mode */
	if (extract_pm(e))
		return -1;

	/* extract source address and destination address/port */
	if (extract_networking_info(e))
		return -1;

	/* extract packet size and rate */
	if (extract_stream_params(e, 0))
		return -1;

	return 0;
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

	return e->pm[dup];
}

char *sdp_extractor_get_src_ip(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return NULL;

	return *e->addr_src[dup] ? e->addr_src[dup] : "N/A";
}

char *sdp_extractor_get_dst_ip(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return NULL;

	return e->addr_dst[dup];
}

uint16_t sdp_extractor_get_dst_port(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->port_dst[dup];
}

int sdp_extractor_get_packet_size(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->packet_size[dup];
}

double sdp_extractor_get_rate(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->rate[dup];
}

int sdp_extractor_get_is_rate_integer(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->is_rate_integer[dup];
}

int sdp_extractor_get_npackets(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->npackets[dup];
}

double sdp_extractor_get_fps(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->fps[dup];
}

int sdp_extractor_get_type(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->type[dup];
}

int sdp_extractor_get_signal(sdp_extractor_t sdp_extractor, int dup)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	if (e->stream_num < dup)
		return -1;

	return e->signal[dup];
}

int sdp_extractor_set_npackets(sdp_extractor_t sdp_extractor, int npackets)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

	return extract_stream_params(e, npackets);
}

void sdp_extractor_uninit(sdp_extractor_t sdp_extractor)
{
	struct sdp_extractor *e = (struct sdp_extractor*)sdp_extractor;

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

