#include <string.h>

#include "sdp_test_util.h"
#include "sdp_stream.h"
#include "sdp_parser.h"
#include "smpte2110_sdp_parser.h"
#include "smpte2022_sdp_parser.h"

#define SET_ATTR_VINFO(m_id, a_id, func, ...) \
	set_attr_vinfo(m_id, a_id, (sdp_attr_func_ptr)func, \
		num_args((sdp_attr_func_ptr )func), __VA_ARGS__)

static int test_generic_smpte2110_get_error(const char *content,
		enum sdp_parse_err expected)
{
	return test_generic(content, expected, NULL, smpte2110);
}

static int missing_required_fmtp_param(enum smpte_2110_attr_param_err missing)
{
	struct {
		enum smpte_2110_attr_param_err param;
		char *entry;
	} required_params[] = {
		{ SMPTE_ERR_SAMPLING, "sampling=YCbCr-4:2:2" },
		{ SMPTE_ERR_DEPTH, "depth=10" },
		{ SMPTE_ERR_WIDTH, "width=1280" },
		{ SMPTE_ERR_HEIGHT, "height=720" },
		{ SMPTE_ERR_EXACTFRAMERATE, "exactframerate=60000/1001" },
		{ SMPTE_ERR_COLORIMETRY, "colorimetry=BT709" },
		{ SMPTE_ERR_PM, "PM=2110GPM" },
		{ SMPTE_ERR_TP, "TP=2110TPN" },
		{ SMPTE_ERR_SSN, "SSN=ST2110-20:2017" },
	};
	char content[300] =
		"v=0\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"m=video 50000 RTP/AVP 112\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 ";
	int i;

	for (i = 0; i < ARRAY_SZ(required_params); i++) {
		if (required_params[i].param == missing)
			continue;

		strcat(content, required_params[i].entry);
		strcat(content, "; "); /* delimiter */
	}
	strcat(content, "\n"); /* end of line */

	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

/******************************************************************************
                              Validator Functions
******************************************************************************/
#define MAX_NUM_DID_SDIDS 10

struct smpte2110_40_did_sdid_validator_info
{
	int code_1;
	int code_2;
};

struct smpte2110_40_fmtp_validator_info
{
	struct smpte2110_40_did_sdid_validator_info dids[MAX_NUM_DID_SDIDS];
	int vpid_code;
};

static int no_specific_fmtp(const struct sdp_attr *attr,
		long long fmt, const char *params)
{
	return ASSERT_INT(attr->type, SDP_ATTR_FMTP) &&
		ASSERT_INT(attr->value.fmtp.fmt->id, fmt) &&
		ASSERT_STR(attr->value.fmtp.params.as.as_str, params);
}

static int no_specific_rtpmap(const struct sdp_attr *attr,
		long long payload_type, const char *encoding_name,
		long long clock_rate, const char *encoding_parameters)
{
	return ASSERT_INT(attr->type, SDP_ATTR_RTPMAP) &&
		ASSERT_INT(attr->value.rtpmap.fmt->id, payload_type) &&
		ASSERT_STR(attr->value.rtpmap.encoding_name.as.as_str,
				encoding_name) &&
		ASSERT_INT(attr->value.rtpmap.clock_rate, clock_rate) &&
		ASSERT_STR(attr->value.rtpmap.encoding_parameters.as.as_str,
				encoding_parameters);
}

static int no_specific_ptime(const struct sdp_attr *attr,
		double packet_time)
{
	return ASSERT_INT(attr->type, SDP_ATTR_PTIME) &&
		ASSERT_FLT(attr->value.ptime.packet_time, packet_time);
}

static int smpte2110_rtpmap(const struct sdp_attr *attr,
		long long payload_type, long long bit_width,
		long long clock_rate, long long num_channels)
{
	return ASSERT_INT(attr->type, SDP_ATTR_RTPMAP) &&
		ASSERT_INT(attr->value.rtpmap.fmt->id, payload_type) &&
		ASSERT_INT(attr->value.rtpmap.encoding_name.as.as_ll,
				bit_width) &&
		ASSERT_INT(attr->value.rtpmap.clock_rate, clock_rate) &&
		ASSERT_INT(attr->value.rtpmap.encoding_parameters.as.as_ll,
				num_channels);
}

static int smpte2110_40_fmtp(const struct sdp_attr *attr,
		struct smpte2110_40_fmtp_validator_info *fv)
{
	struct smpte2110_40_fmtp_params *params =
			(struct smpte2110_40_fmtp_params *)
					attr->value.fmtp.params.as.as_ptr;
	struct smpte2110_40_did_sdid *did;
	struct smpte2110_40_did_sdid_validator_info *dv;
	int res = 1;
	int d_cnt = 0;

	for (did = params->dids; did; did = did->next) {
		dv = &fv->dids[d_cnt++];
		res &= ASSERT_INT(did->code_1, dv->code_1);
		res &= ASSERT_INT(did->code_2, dv->code_2);
	}
	res &= ASSERT_INT(params->vpid_code, fv->vpid_code);
	return res;
}

static int no_specific_framerate(const struct sdp_attr *attr,
		double frame_rate)
{
	return ASSERT_INT(attr->type, SDP_ATTR_FRAMERATE) &&
		ASSERT_FLT(attr->value.framerate.frame_rate, frame_rate);
}

static int no_specific_tag(const struct group_identification_tag *tag,
		const char *name, struct sdp_media *media)
{
	return ASSERT_STR(tag->identification_tag, name) &&
		ASSERT_PTR(tag->media, media);
}

static int no_specific_group(struct sdp_session *session,
		const struct sdp_attr *attr, struct group_validator_info *gvi)
{
	struct sdp_media *media;
	struct sdp_media *all_medias[MAX_NUM_MEDIAS];
	struct group_identification_tag *tag;
	int m_cnt = 0, t_cnt = 0;
	int res;

	res = ASSERT_INT(attr->type, SDP_ATTR_GROUP) &&
		ASSERT_STR(attr->value.group.semantic, gvi->semantic) &&
		ASSERT_INT(attr->value.group.num_tags, gvi->tag_count);

	if (!res)
		return 0;

	for (media = session->media; media; media = media->next)
		all_medias[m_cnt++] = media;

	for (tag = attr->value.group.tag; tag; tag = tag->next) {
		struct tag_validator_info *tv = &gvi->tags[t_cnt++];

		media = (tv->media_id == -1) ? NULL : all_medias[tv->media_id];
		if (tv->name)
			res &= ASSERT_RES(no_specific_tag(tag, tv->name,
					media));
	}
	return res;
}

int num_args(sdp_attr_func_ptr func) {
	int num_args = 0;
	if (func == (sdp_attr_func_ptr)no_specific_fmtp)
		num_args = 2;
	else if (func == (sdp_attr_func_ptr)no_specific_rtpmap)
		num_args = 4;
	else if (func == (sdp_attr_func_ptr)no_specific_ptime)
		num_args = 1;
	else if (func == (sdp_attr_func_ptr)no_specific_framerate)
		num_args = 1;
	else if (func == (sdp_attr_func_ptr)no_specific_group)
		num_args = 1;
	else if (func == (sdp_attr_func_ptr)smpte2110_rtpmap)
		num_args = 4;
	else if (func == (sdp_attr_func_ptr)smpte2110_40_fmtp)
		num_args = 1;
	return num_args;
}

void set_attr_vinfo(int m_id, int a_id, sdp_attr_func_ptr func,
		int num_args, ...)
{
	va_list vl;
	struct attr_validator_info *av = (m_id == -1) ?
			&validator_info.attributes[a_id] :
			&validator_info.medias[m_id].attributes[a_id];

	av->func = func;
	va_start(vl, num_args);
	if (func == (sdp_attr_func_ptr)no_specific_fmtp) {
		av->args[0].as.as_ll = va_arg(vl, int);
		av->args[1].as.as_str = va_arg(vl, char*);
	} else if (func ==  (sdp_attr_func_ptr)no_specific_rtpmap) {
		av->args[0].as.as_ll = va_arg(vl, int);
		av->args[1].as.as_str = va_arg(vl, char*);
		av->args[2].as.as_ll = va_arg(vl, int);
		av->args[3].as.as_str = va_arg(vl, char*);
	} else if (func == (sdp_attr_func_ptr)no_specific_ptime) {
		av->args[0].as.as_d = va_arg(vl, double);
	} else if (func == (sdp_attr_func_ptr)no_specific_framerate) {
		av->args[0].as.as_d = va_arg(vl, double);
	} else if (func == (sdp_attr_func_ptr)no_specific_group) {
		av->args[0].as.as_ptr = va_arg(vl, void*);
	} else if (func == (sdp_attr_func_ptr)smpte2110_rtpmap) {
		av->args[0].as.as_ll = va_arg(vl, int);
		av->args[1].as.as_ll = va_arg(vl, int);
		av->args[2].as.as_ll = va_arg(vl, int);
		av->args[3].as.as_ll = va_arg(vl, int);
	} else if (func == (sdp_attr_func_ptr)smpte2110_40_fmtp) {
		av->args[0].as.as_ptr = va_arg(vl, void*);
	}
	va_end(vl);
}

int assert_attr(struct sdp_session *session,
		struct sdp_attr *attr, struct attr_validator_info *av)
{
	int res = 0;
	if (av->func ==  NULL) {
		res = 1;
	} else if (av->func == (sdp_attr_func_ptr)no_specific_fmtp) {
		res = no_specific_fmtp(attr, av->args[0].as.as_ll,
			av->args[1].as.as_str);
	} else if (av->func == (sdp_attr_func_ptr)no_specific_rtpmap) {
		res = no_specific_rtpmap(attr, av->args[0].as.as_ll,
			av->args[1].as.as_str, av->args[2].as.as_ll,
			av->args[3].as.as_str);
	} else if (av->func == (sdp_attr_func_ptr)no_specific_ptime) {
		res = no_specific_ptime(attr, av->args[0].as.as_d);
	} else if (av->func == (sdp_attr_func_ptr)no_specific_framerate) {
		res = no_specific_framerate(attr, av->args[0].as.as_d);
	} else if (av->func == (sdp_attr_func_ptr)no_specific_framerate) {
		res = no_specific_framerate(attr, av->args[0].as.as_d);
	} else if (av->func == (sdp_attr_func_ptr)smpte2110_rtpmap) {
		res = smpte2110_rtpmap(attr, av->args[0].as.as_ll,
			av->args[1].as.as_ll, av->args[2].as.as_ll,
			av->args[3].as.as_ll);
	} else if (av->func == (sdp_attr_func_ptr)smpte2110_40_fmtp) {
		res = smpte2110_40_fmtp(attr,
			(struct smpte2110_40_fmtp_validator_info*)av->args[0].as.as_ptr);
	} else if (av->func == (sdp_attr_func_ptr)no_specific_group) {
		res = no_specific_group(session, attr,
			(struct group_validator_info*)av->args[0].as.as_ptr);
	} else {
		res = assert_error("Unsupported assertion function %p.\n",
			av->func);
	}
	return res;
}

/******************************************************************************
                                   Tests
******************************************************************************/
REG_TEST(test001, "SMPTE2110-10 annex B example SDP")
{
	char *content =
		"v=0\n"
		"o=- 123456 11 IN IP4 192.168.100.2\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"i=this example is for 720p video at 59.94\n"
		"t=0 0\n"
		"a=recvonly\n"
		"a=group:DUP primary secondary\n"
		"m=video 50000 RTP/AVP 112\n"
		"c=IN IP4 239.100.9.10/32\n"
		"a=source-filter:incl IN IP4 239.100.9.10 192.168.100.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:primary\n"
		"m=video 50020 RTP/AVP 112\n"
		"c=IN IP4 239.101.9.10/32\n"
		"a=source-filter:incl IN IP4 239.101.9.10 192.168.101.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:secondary\n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test002, "Minimum supported set")
{
	char *content =
		"v=0\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"m=video 50000 RTP/AVP 112\n"
		"c=IN IP4 239.100.9.10/32\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"m=video 50020 RTP/AVP 112\n"
		"c=IN IP4 239.101.9.10/32\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test003, "Fail on missing required v=")
{
	char *content =
		"m=video 50000 RTP/AVP 112\n"
		"c=IN IP4 239.100.9.10/32\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"m=video 50020 RTP/AVP 112\n"
		"c=IN IP4 239.101.9.10/32\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test004, "Fail on nothing beyond v=")
{
	char *content =
		"v=0\n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test005, "Allow no m=")
{
	char *content =
		"v=0\n"
		"o=- 123456 11 IN IP4 192.168.100.2\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"i=this example is for 720p video at 59.94\n"
		"t=0 0\n"
		"a=recvonly\n"
		"a=group:DUP primary secondary\n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test006, "Parse v=, m= and a=fmtp:<fmt> only")
{
	char *content =
		"v=0\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"m=video 50000 RTP/AVP 112\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test007, "a=fmtp: pass on missing default parameters")
{
	char *content =
		"v=0\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"m=video 50000 RTP/AVP 112\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test008, "a=fmtp: fail on missing required sampling=")
{
	return missing_required_fmtp_param(SMPTE_ERR_SAMPLING);
}

REG_TEST(test009, "a=fmtp: fail on missing required depth=")
{
	return missing_required_fmtp_param(SMPTE_ERR_DEPTH);
}

REG_TEST(test010, "a=fmtp: fail on missing required width=")
{
	return missing_required_fmtp_param(SMPTE_ERR_WIDTH);
}

REG_TEST(test011, "a=fmtp: fail on missing required height=")
{
	return missing_required_fmtp_param(SMPTE_ERR_HEIGHT);
}

REG_TEST(test012, "a=fmtp: fail on missing required exactframerate=")
{
	return missing_required_fmtp_param(SMPTE_ERR_EXACTFRAMERATE);
}

REG_TEST(test013, "a=fmtp: fail on missing required colorimetry=")
{
	return missing_required_fmtp_param(SMPTE_ERR_COLORIMETRY);
}

REG_TEST(test014, "a=fmtp: fail on missing required PM=")
{
	return missing_required_fmtp_param(SMPTE_ERR_PM);
}

REG_TEST(test015, "a=fmtp: fail on missing required TP=")
{
	return missing_required_fmtp_param(SMPTE_ERR_TP);
}

REG_TEST(test016, "a=fmtp: fail on missing required SSN=")
{
	return missing_required_fmtp_param(SMPTE_ERR_SSN);
}

static int assert_source_filter(struct sdp_session *session)
{
	struct sdp_media *media;
	int cnt_m;

	/* loop over all m= blocks */
	for (media = sdp_media_get(session, SDP_MEDIA_TYPE_VIDEO), cnt_m = 0;
		media; media = sdp_media_get_next(media), cnt_m++) {
		struct sdp_attr *attr;
		int cnt_a;

		if (1 < cnt_m) {
			test_log("%s(): excess media clauses\n", __func__);
			return -1;
		}

		/* loop over all a=source-filter blocks */
		for (attr = sdp_media_attr_get(media, SDP_ATTR_SOURCE_FILTER),
			cnt_a = 0; attr;
			attr = sdp_attr_get_next(attr), cnt_a++) {
			struct sdp_attr_value_source_filter *source_filter;
			struct {
				char *dst_addr;
				char *src_addr;
			} addresses[2] = {
				{
					"239.100.9.10", /* dst_addr */
					"192.168.100.2" /* src_addr */
				},
				{
					"239.101.9.10", /* dst_addr */
					"192.168.101.2" /* src_addr */
				}
			};

			if (0 < cnt_a) {
				test_log("%s(): excess source-filter "
					"attributes\n", __func__);
				return -1;
			}

			/* assert attribute type */
			if (attr->type != SDP_ATTR_SOURCE_FILTER) {
				test_log("%s(): bad attr type: %d\n",
					__func__, attr->type);
				return -1;
			}

			source_filter = &attr->value.source_filter;

			/* assert source-filter mode */
			if (source_filter->mode != SDP_ATTR_SRC_FLT_INCL) {
				test_log("%s(): bad source-filter mode: %d\n",
					__func__, source_filter->mode);
				return -1;
			}

			/* assert source-filter net type */
			if (source_filter->spec.nettype != SDP_CI_NETTYPE_IN) {
				test_log("%s(): bad source-filter nettype: "
					"%d\n", __func__,
					source_filter->spec.nettype);
				return -1;
			}

			/* assert source-filter addr type */
			if (source_filter->spec.addrtype !=
					SDP_CI_ADDRTYPE_IPV4) {
				test_log("%s(): bad source-filter addrtype: "
					"%d\n", __func__,
					source_filter->spec.addrtype);
				return -1;
			}

			/* assert source-filter dst addr */
			if (strncmp(addresses[cnt_m].dst_addr,
					source_filter->spec.dst_addr,
					sizeof(source_filter->spec.dst_addr))) {
				test_log("%s(): bad source-filter dst-addr: "
					"%s\n", __func__,
					source_filter->spec.dst_addr);
				return -1;
			}

			/* assert source-filter src addr */
			if (strncmp(addresses[cnt_m].src_addr,
					source_filter->spec.src_list.addr,
					sizeof(
					source_filter->spec.src_list.addr))) {
				test_log("%s(): bad source-filter src-addr: "
					"%s\n", __func__,
					source_filter->spec.src_list.addr);
				return -1;
			}

			/* assert source-filter has a single src addr */
			if (source_filter->spec.src_list.next) {
				test_log("%s() bad source_filter src_list.next "
					"pointer: %p\n", __func__,
					source_filter->spec.src_list.next);
				return -1;
			}

			/* assert source-filter has a single src addr */
			if (source_filter->spec.src_list_len != 1) {
				test_log("%s() bad source_filter src_list_len: "
					"%d", __func__,
					source_filter->spec.src_list_len);
				return -1;
			}

		}

		if (cnt_a != 1) {
			test_log("%s() Wrong number of source-filter "
				"attributes: %d\n", __func__, cnt_a);
			return -1;
		}
	}

	if (cnt_m != 2) {
		test_log("%s() Wrong number of media clauses: %d\n",
			__func__, cnt_m);
		return -1;
	}

	return 0;
}

REG_TEST(test017, "a=source-filter: <filter-mode> <filter-spec>")
{
	char *content =
		"v=0\n"
		"o=- 123456 11 IN IP4 192.168.100.2\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"i=this example is for 720p video at 59.94\n"
		"t=0 0\n"
		"a=recvonly\n"
		"a=group:DUP primary secondary\n"
		"m=video 50000 RTP/AVP 112\n"
		"c=IN IP4 239.100.9.10/32\n"
		"a=source-filter:incl IN IP4 239.100.9.10 192.168.100.2 "
			"192.168.100.3\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:primary\n"
		"m=video 50020 RTP/AVP 112\n"
		"c=IN IP4 239.101.9.10/32\n"
		"a=source-filter:incl IN IP4 239.101.9.10 192.168.101.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:secondary\n";

	return test_generic(content, SDP_PARSE_OK, assert_source_filter,
			smpte2110);
}

static int assert_mid(struct sdp_session *session)
{
	struct sdp_media *media;
	int cnt_m;

	/* loop over all m= blocks */
	for (media = sdp_media_get(session, SDP_MEDIA_TYPE_VIDEO), cnt_m = 0;
		media; media = sdp_media_get_next(media), cnt_m++) {
		struct sdp_attr *attr;
		int cnt_a;

		if (1 < cnt_m) {
			test_log("%s(): excess media clauses\n", __func__);
			return -1;
		}

		/* loop over all a=mid blocks */
		for (attr = sdp_media_attr_get(media, SDP_ATTR_MID),
			cnt_a = 0; attr;
			attr = sdp_attr_get_next(attr), cnt_a++) {
			struct sdp_attr_value_mid *mid;
			char *identification_tag[2] = {
				"primary", "secondary"
			};

			if (0 < cnt_a) {
				test_log("%s(): excess media stream "
					"identification attributes\n",
					__func__);
				return -1;
			}

			/* assert attribute type */
			if (attr->type != SDP_ATTR_MID) {
				test_log("%s(): bad attr type: %d\n",
					__func__, attr->type);
				return -1;
			}

			mid = &attr->value.mid;

			/* assert identification tag */
			if (strncmp(mid->identification_tag,
					identification_tag[cnt_m],
					strlen(mid->identification_tag))) {
				test_log("%s(): bad identification tag: %s\n",
					__func__, mid->identification_tag);
				return -1;
			}

		}

		if (cnt_a != 1) {
			test_log("%s() Wrong number of media steram "
				"identification attributes: %d\n", __func__,
				cnt_a);
			return -1;
		}
	}

	if (cnt_m != 2) {
		test_log("%s() Wrong number of media clauses: %d\n",
			__func__, cnt_m);
		return -1;
	}

	return 0;
}

REG_TEST(test018, "a=mid: <identification_tag>")
{
	char *content =
		"v=0\n"
		"o=- 123456 11 IN IP4 192.168.100.2\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"i=this example is for 720p video at 59.94\n"
		"t=0 0\n"
		"a=recvonly\n"
		"a=group:DUP primary secondary\n"
		"m=video 50000 RTP/AVP 112\n"
		"c=IN IP4 239.100.9.10/32\n"
		"a=source-filter:incl IN IP4 239.100.9.10 192.168.100.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:primary\n"
		"m=video 50020 RTP/AVP 112\n"
		"c=IN IP4 239.101.9.10/32\n"
		"a=source-filter:incl IN IP4 239.101.9.10 192.168.101.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:secondary\n";

	return test_generic(content, SDP_PARSE_OK, assert_mid, smpte2110);
}

static int assert_group(struct sdp_session *session)
{
	struct sdp_attr *attr;
	int cnt_a;

	/* loop over all a=group blocks (should be only one) */
	for (attr = sdp_session_attr_get(session, SDP_ATTR_GROUP), cnt_a = 0;
			attr; attr = sdp_attr_get_next(attr), cnt_a++) {
		struct sdp_attr_value_group *group;
		struct group_identification_tag *tag;
		char *identification_tag[2] = {
			"primary", "secondary"
		};
		int i;

		if (0 < cnt_a) {
			test_log("%s(): excess media stream group attributes\n",
				__func__);
			return -1;
		}

		/* assert attribute type */
		if (attr->type != SDP_ATTR_GROUP) {
			test_log("%s(): bad attr type: %d\n", __func__,
				attr->type);
			return -1;
		}

		group = &attr->value.group;

		/* assert that group semantic is "DUP" */
		if (strncmp(group->semantic, "DUP", strlen("DUP"))) {
			test_log("%s(): bad group semantic: %s\n", __func__,
				group->semantic);
			return -1;
		}

		/* assert that number of tags in group is 2 */
		if (group->num_tags != 2) {
			test_log("%s(): bad number of tags: %d\n", __func__,
				group->num_tags);
			return -1;
		}

		/* assert group identification tags */
		for (tag = group->tag, i = 0; tag && i < 2;
				tag = tag->next, i++) {
			if (strncmp(tag->identification_tag,
					identification_tag[i],
					strlen(identification_tag[i]))) {
				test_log("%s(): bad group identification tag: "
					"%s\n", __func__,
					tag->identification_tag);
				return -1;
			}
		}

		/* assert that there are no excess tags */
		if (tag) {
			test_log("%s(): last group identification tag points to"
				" dangling location: %p\n", __func__, tag);
			return -1;
		}
	}

	/* assert a single media group attribute */
	if (cnt_a != 1) {
		test_log("%s() Wrong number of media steram group attributes: "
			"attributes: %d\n", __func__, cnt_a);
		return -1;
	}

	return 0;
}

static int assert_no_group(struct sdp_session *session)
{
	struct sdp_attr *attr;

	attr = sdp_session_attr_get(session, SDP_ATTR_GROUP);
	if (attr) {
		test_log("%s(): found non existing media group"
			" identification\n", __func__);
		return -1;
	}

	return 0;
}

REG_TEST(test019, "a=group:DUP <primary> <secondary>")
{
	char *content =
		"v=0\n"
		"o=- 123456 11 IN IP4 192.168.100.2\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"i=this example is for 720p video at 59.94\n"
		"t=0 0\n"
		"a=recvonly\n"
		"a=group:DUP primary secondary\n"
		"m=video 50000 RTP/AVP 112\n"
		"c=IN IP4 239.100.9.10/32\n"
		"a=source-filter:incl IN IP4 239.100.9.10 192.168.100.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:primary\n"
		"m=video 50020 RTP/AVP 112\n"
		"c=IN IP4 239.101.9.10/32\n"
		"a=source-filter:incl IN IP4 239.101.9.10 192.168.101.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:secondary\n";

	return test_generic(content, SDP_PARSE_OK, assert_group, smpte2110);
}

REG_TEST(test020, "Identify no a=group attribute")
{
	char *content =
		"v=0\n"
		"o=- 123456 11 IN IP4 192.168.100.2\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"i=this example is for 720p video at 59.94\n"
		"t=0 0\n"
		"a=recvonly\n"
		"m=video 50000 RTP/AVP 112\n"
		"c=IN IP4 239.100.9.10/32\n"
		"a=source-filter:incl IN IP4 239.100.9.10 192.168.100.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:primary\n";

	return test_generic(content, SDP_PARSE_OK, assert_no_group, smpte2110);
}

REG_TEST(test021, "SSN quoted value")
{
	char *content =
		"v=0\n"
		"o=- 1443716955 1443716955 IN IP4 192.168.1.230\n"
		"s=st2110 stream\n"
		"t=0 0\n"
		"m=video 20000 RTP/AVP 96\n"
		"c=IN IP4 239.0.1.2/64\n"
		"a=source-filter:incl IN IP4 239.0.1.2 192.168.0.1\n"
		"a=rtpmap:96 raw/90000\n"
		"a=fmtp:96 sampling=YCbCr-4:2:2; width=720; height=486; "
			"exactframerate=30000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT601; PM=2110GPM; "
			"SSN=\"ST2110-20:2017\"; TP=2110TPN; interlace=1\n"
		"a=mediaclk:direct=0\n"
		"a=ts-refclk:localmac=40-a3-6b-a0-2b-d2\n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test022, "a=fmtp for non raw video format")
{
	char *content =
		"v=0\n"
		"o=- 804326665 0 IN IP4 192.168.3.77\n"
		"s=Gefei XIO9101 2110\n"
		"t=0 0\n"
		"m=video 5000 RTP/AVP 96\n"
		"c=IN IP4 239.10.10.100/96\n"
		"a=rtpmap:96 raw/90000\n"
		"a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; "
			"exactframerate=30000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110BPM; "
			"SSN=\"ST2110-20:2017\"; interlace; TP=2110TPN\n"
		"a=tsrefclk:ptp=IEEE1588-2008:08-00-11-FF-FE-22-39-E4:125\n"
		"a=mediaclk:direct=0\n"
		"a=mid:VID\n"
		"m=audio 5010 RTP/AVP 110\n"
		"c=IN IPV4 239.10.10.110/96\n"
		"a=rtpmap:110 L24/48000/2\n"
		"a=fmtp:110 channel-order=SMPTE2110.(ST)\n"
		"a=ptime:1.000\n"
		"a=tsrefclk:ptp=IEEE1588-2008:08-00-11-FF-FE-22-39-E4:125\n"
		"a=mediaclk:direct=0\n"
		"a=mid:AUD\n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test023, "no ttl for c=<ipv4-addr>")
{
	char *content =
		"v=0\n"
		"o=- 804326665 0 IN IP4 192.168.3.77\n"
		"s=Gefei XIO9101 2110\n"
		"t=0 0\n"
		"m=video 5000 RTP/AVP 100\n"
		"c=IN IP4 239.10.10.100\n"
		"a=rtpmap:96 raw/90000\n"
		"a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; "
			"exactframerate=30000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110BPM; "
			"SSN=\"ST2110-20:2017\"; interlace; TP=2110TPN\n"
		"a=tsrefclk:ptp=IEEE1588-2008:08-00-11-FF-FE-22-39-E4:125\n"
		"a=mediaclk:direct=0\n"
		"a=mid:VID\n";

	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test024, "sampling parameters")
{
	char *sdp_prefix =
		"v=0\n"
		"o=- 804326665 0 IN IP4 192.168.3.77\n"
		"s=Gefei XIO9101 2110\n"
		"t=0 0\n"
		"m=video 5000 RTP/AVP 96\n"
		"c=IN IP4 239.10.10.100/96\n"
		"a=rtpmap:96 raw/90000\n"
		"a=fmtp:96";
	char *sdp_suffix =
		"width=1920; height=1080; exactframerate=30000/1001; depth=10; "
		"TCS=SDR; colorimetry=BT709; PM=2110BPM; "
		"SSN=\"ST2110-20:2017\"; interlace; TP=2110TPN\n"
		"a=tsrefclk:ptp=IEEE1588-2008:08-00-11-FF-FE-22-39-E4:125\n"
		"a=mediaclk:direct=0\n"
		"a=mid:VID\n";
	char *sampling_parameters[] = {
		"YCbCr-4:4:4",
		"YCbCr-4:2:2",
		"YCbCr-4:2:0",
		"CLYCbCr-4:4:4",
		"CLYCbCr-4:2:2",
		"CLYCbCr-4:2:0",
		"ICtCp-4:4:4",
		"ICtCp-4:2:2",
		"ICtCp-4:2:0",
		"RGB",
		"XYZ",
		"KEY",
	};
	char sdp[1024];
	int i;

	for (i = 0; i < ARRAY_SZ(sampling_parameters); i++) {
		snprintf(sdp, sizeof(sdp), "%s sampling=%s; %s", sdp_prefix,
			sampling_parameters[i], sdp_suffix);

		test_log(" sampling=%s\n", sampling_parameters[i]);
		if (test_generic_smpte2110_get_error(sdp, SDP_PARSE_OK))
			return SDP_PARSE_ERROR;
	}

	return SDP_PARSE_OK;
}

/******************************************************************************
                              Some Comp Tests
******************************************************************************/
static const char *no_specific_content =
		"v=0\n"
		"s=SDP test\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100 101 102 103\n"
		"a=rtpmap:100 something/10000\n"
		"a=rtpmap:101 something/20000/params\n"
		"a=fmtp:102 something else\n"
		"a=fmtp:103 something else\n"
		"m=audio 60000 RTP/AVP 200 201 202 203\n"
		"a=rtpmap:200 something/10000\n"
		"a=rtpmap:201 something/20000/params\n"
		"a=fmtp:202 something else\n"
		"a=fmtp:203 something else\n";

REG_TEST(test025, "PASS - SDP with no specific interpretation/restrictions")
{
	init_session_validator();
	validator_info.media_count = 2;
	validator_info.medias[0].attr_count = 4;
	SET_ATTR_VINFO(0, 0, no_specific_rtpmap, 100, "something", 10000, "");
	SET_ATTR_VINFO(0, 1, no_specific_rtpmap, 101, "something", 20000,
			"params");
	SET_ATTR_VINFO(0, 2, no_specific_fmtp,   102, "something else");
	SET_ATTR_VINFO(0, 3, no_specific_fmtp,   103, "something else");
	validator_info.medias[1].attr_count = 4;
	SET_ATTR_VINFO(1, 0, no_specific_rtpmap, 200, "something", 10000, "");
	SET_ATTR_VINFO(1, 1, no_specific_rtpmap, 201, "something", 20000,
			"params");
	SET_ATTR_VINFO(1, 2, no_specific_fmtp,   202, "something else");
	SET_ATTR_VINFO(1, 3, no_specific_fmtp,   203, "something else");
	return test_generic(no_specific_content, SDP_PARSE_OK, assert_session,
			no_specific);
}

/******************************************************************************
                                SMPTE Type
******************************************************************************/
REG_TEST(smpte2110_sub_types_1,
		"FAIL - smpte2110 unknown media sub type audio 1")
{
	char *content =
		"v=0\n"
		"s=SDP test: sub types 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 raw/10000\n";
	return test_generic(content, SDP_PARSE_NOT_SUPPORTED, NULL, smpte2110);
}

REG_TEST(smpte2110_sub_types_2,
		"FAIL - smpte2110 unknown media sub type audio 2")
{
	char *content =
		"v=0\n"
		"s=SDP test: sub types 2\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/10000\n";
	return test_generic(content, SDP_PARSE_NOT_SUPPORTED, NULL, smpte2110);
}

REG_TEST(smpte2110_sub_types_3,
		"FAIL - smpte2110 unknown media sub type video 1")
{
	char *content =
		"v=0\n"
		"s=SDP test: sub types 3\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000\n";
	return test_generic(content, SDP_PARSE_NOT_SUPPORTED, NULL, smpte2110);
}

REG_TEST(smpte2110_sub_types_4,
		"FAIL - smpte2110 multiple formats")
{
	char *content =
		"v=0\n"
		"s=SDP test: sub types 4\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100 101\n"
		"a=rtpmap:100 raw/90000\n"
		"a=rtpmap:101 smpte291/10000\n"
		"m=audio 50000 RTP/AVP 100 101 102\n"
		"a=rtpmap:100 L16/90000\n"
		"a=rtpmap:101 L24/90000\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(smpte2110_sub_types_5,
		"PASS - smpte2110 multiple formats")
{
	char *content =
		"v=0\n"
		"s=SDP test: sub types 5\n"
		"m=video 50000 RTP/AVP 100 101\n"
		"a=rtpmap:100 raw/90000\n"
		"a=rtpmap:101 smpte291/10000\n"
		"a=fmtp:100 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"m=audio 50000 RTP/AVP 100 101\n"
		"a=rtpmap:100 L16/90000\n"
		"a=rtpmap:101 L24/90000\n";
	init_session_validator();
	validator_info.medias[0].fmt_count = 2;
	validator_info.medias[0].formats[0].id = 100;
	validator_info.medias[0].formats[0].sub_type = SMPTE_2110_SUB_TYPE_20;
	validator_info.medias[0].formats[1].id = 101;
	validator_info.medias[0].formats[1].sub_type = SMPTE_2110_SUB_TYPE_40;
	validator_info.medias[1].fmt_count = 2;
	validator_info.medias[1].formats[0].id = 100;
	validator_info.medias[1].formats[0].sub_type = SMPTE_2110_SUB_TYPE_30;
	validator_info.medias[1].formats[1].id = 101;
	validator_info.medias[1].formats[1].sub_type = SMPTE_2110_SUB_TYPE_30;
	return test_generic(content, SDP_PARSE_OK, assert_session, smpte2110);
}

/******************************************************************************
                                 Payload Type
******************************************************************************/
REG_TEST(test_rtpmap_payload_type_1,
		"FAIL - payload type is not an int")
{
	char *content =
		"v=0\n"
		"s=SDP test: payload types 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:xxx L24/10000\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_rtpmap_payload_type_2,
		"FAIL - payload type - not found (rtpmap)")
{
	char *content =
		"v=0\n"
		"s=SDP test: payload types 2\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 101 102 104\n"
		"a=rtpmap:101 L24/10000\n"
		"a=rtpmap:102 L24/10000\n"
		"a=rtpmap:103 L24/10000\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_rtpmap_payload_type_3,
		"FAIL - payload type - not found (fmtp)")
{
	char *content =
		"v=0\n"
		"t=0 0\n"
		"s=SDP test: payload types 3\n"
		"m=audio 50000 RTP/AVP 101 102 104\n"
		"a=fmtp:101 something\n"
		"a=fmtp:102 something\n"
		"a=fmtp:103 something\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_rtpmap_payload_type_4,
		"PASS - payload type - match eventually")
{
	char *content =
		"v=0\n"
		"s=SDP test: payload types 4\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 101 105 104 102 106 103\n"
		"a=fmtp:101 something\n"
		"a=fmtp:102 something\n"
		"a=fmtp:103 something\n"
		"a=fmtp:104 something\n"
		"a=fmtp:105 something\n"
		"a=fmtp:106 something\n";
	return test_generic(content, SDP_PARSE_OK, NULL, no_specific);
}

REG_TEST(test_rtpmap_payload_type_5,
		"PASS - payload type - formats with no attributes")
{
	char *content =
		"v=0\n"
		"s=SDP test: payload types 5\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 0 1 2 3 100 200\n";
	return test_generic(content, SDP_PARSE_OK, NULL, no_specific);
}

/******************************************************************************
                                Encoding Name
******************************************************************************/
REG_TEST(test_rtpmap_encoding_name_1,
		"FAIL - rtpmap encoding name not specified")
{
	char *content =
		"v=0\n"
		"s=SDP test: rtp encoding name 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 \n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

/******************************************************************************
                                  Bit Depth
******************************************************************************/
REG_TEST(test_rtpmap_bit_depth_1, "PASS - smpte2110 rtpmap bit-depth 16")
{
	char *content =
		"v=0\n"
		"s=SDP test: rtp bit depth 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L16/10000\n";
	init_session_validator();
	SET_ATTR_VINFO(0, 0, smpte2110_rtpmap, 100, 16, 10000, 1);
	return test_generic(content, SDP_PARSE_OK, NULL, smpte2110);
}

REG_TEST(test_rtpmap_bit_depth_2, "PASS - smpte2110 rtpmap bit-depth 24")
{
	char *content =
		"v=0\n"
		"s=SDP test: rtp bit depth 2\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000\n";
	init_session_validator();
	SET_ATTR_VINFO(0, 0, smpte2110_rtpmap, 100, 25, 10000, 1);
	return test_generic(content, SDP_PARSE_OK, NULL, smpte2110);
}

/******************************************************************************
                                 Clock Rate
******************************************************************************/
REG_TEST(test_rtpmap_clock_rate_1, "FAIL - rtpmap clock-rate not specified")
{
	char *content =
		"v=0\n"
		"s=SDP test: clock rate 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_rtpmap_clock_rate_2, "FAIL - rtpmap clock-rate not int")
{
	char *content =
		"v=0\n"
		"s=SDP test: clock rate 2\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/abc\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_rtpmap_clock_rate_3, "FAIL - rtpmap clock-rate 0")
{
	char *content =
		"v=0\n"
		"s=SDP test: clock rate 3\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/0\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

/******************************************************************************
                                 Num Channels
******************************************************************************/
REG_TEST(test_rtpmap_num_channels_1,
		"FAIL - smpte2110 rtpmap num channels not int")
{
	char *content =
		"v=0\n"
		"s=SDP test: num channels 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000/abc\n";
	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test_rtpmap_num_channels_2, "FAIL - smpte2110 rtpmap num channels 0")
{
	char *content =
		"v=0\n"
		"s=SDP test: num channels 2\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000/0\n";
	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test_rtpmap_num_channels_3,
		"PASS - smpte2110 rtpmap num channels empty string")
{
	char *content =
		"v=0\n"
		"s=Testing rtpmap num channels 3\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000/\n";

	init_session_validator();
	SET_ATTR_VINFO(0, 0, smpte2110_rtpmap, 100, 24, 10000, 1);
	return test_generic(content, SDP_PARSE_OK, assert_session, smpte2110);
}

REG_TEST(test_rtpmap_num_channels_4,
		"PASS - smpte2110 rtpmap num channels default (NULL)")
{
	char *content =
		"v=0\n"
		"s=Testing rtpmap num channels 4\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000\n";

	init_session_validator();
	SET_ATTR_VINFO(0, 0, smpte2110_rtpmap, 100, 24, 10000, 1);
	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test_rtpmap_num_channels_5,
		"PASS - smpte2110 rtpmap num channels specified.")
{
	char *content =
		"v=0\n"
		"s=Testing rtpmap num channels 5\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000/4\n";

	init_session_validator();
	SET_ATTR_VINFO(0, 0, smpte2110_rtpmap, 100, 24, 10000, 4);
	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

/******************************************************************************
                                   Ptime
******************************************************************************/
REG_TEST(test_ptime_1, "FAIL - smpte2110 ptime not specified.")
{
	char *content =
		"v=0\n"
		"s=SDP test: ptime 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_ptime_2, "FAIL - smpte2110 ptime not int.")
{
	char *content =
		"v=0\n"
		"s=SDP test: ptime 2\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:xxx\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_ptime_3, "FAIL - smpte2110 ptime 0.")
{
	char *content =
		"v=0\n"
		"s=SDP test: ptime 3\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:0\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_ptime_4, "PASS - smpte2110 ptime int.")
{
	char *content =
		"v=0\n"
		"s=SDP test: ptime 4\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:100\n";
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_ptime, 100.0);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_ptime_5, "PASS - smpte2110 ptime double.")
{
	char *content =
		"v=0\n"
		"s=SDP test: ptime 5\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:99.5123\n";
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_ptime, 99.5123);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

/******************************************************************************
                                 Framerate
******************************************************************************/
REG_TEST(test_framerate_1, "FAIL - smpte2110 framerate not a number.")
{
	char *content =
		"v=0\n"
		"s=SDP test: framerate 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=framerate:xxx\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_framerate_2, "FAIL - smpte2110 framerate 0.")
{
	char *content =
		"v=0\n"
		"s=SDP test: framerate 2\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=framerate:0\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_framerate_3, "PASS - smpte2110 framerate int.")
{
	char *content =
		"v=0\n"
		"s=SDP test: framerate 3\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=framerate:100\n";
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_framerate, 100.0);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_framerate_4, "PASS - smpte2110 framerate double.")
{
	char *content =
		"v=0\n"
		"s=SDP test: framerate 4\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=framerate:99.5123\n";
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_framerate, 99.5123);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

/******************************************************************************
                                Smpte2110-40
******************************************************************************/
REG_TEST(test_smpte_40_1, "PASS - smpte2110 no fmtp.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 1\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n";
	return test_generic(content, SDP_PARSE_OK, NULL, smpte2110);
}

REG_TEST(test_smpte_40_2, "PASS - smpte2110 empty fmtp.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 2\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100\n";
	return test_generic(content, SDP_PARSE_OK, NULL, smpte2110);
}

REG_TEST(test_smpte_40_3, "PASS - smpte2110-40 unknown fmtp params.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 3\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 "
			"DID_SDID={0x00,0x00};"
			"DID_SDID={0x00,0x00};"
			"ssn=1;"
			"DID_SDID={0x00,0x00};\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_smpte_40_4, "FAIL - smpte2110-40 one DID_SDID bad format 1.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 4\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 DID_SDID\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_smpte_40_5, "FAIL - smpte2110-40 one DID_SDID bad format 2.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 5\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 DID_SDID=\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_smpte_40_6, "FAIL - smpte2110-40 one DID_SDID bad format 3.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 6\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 DID_SDID={0x12,0xXY}\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_smpte_40_7, "PASS - smpte2110-40 one DID_SDID valid.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 7\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 DID_SDID={0x12,0xfF}\n";

	struct smpte2110_40_fmtp_validator_info fv1 = { { { 0x12, 0xff } }, 0 };
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_rtpmap, 100, "smpte291", 90000, "");
	SET_ATTR_VINFO(0, 1, smpte2110_40_fmtp, &fv1);
	return test_generic(content, SDP_PARSE_OK, assert_session, smpte2110);
}
REG_TEST(test_smpte_40_8, "PASS - smpte2110 multiple DID_SDID, mixed spaces.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 8\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 "
			"DID_SDID={0xaa,0xAA};   "
			"DID_SDID={0xbb,0xBB};"
			"DID_SDID={0xcc,0xCC}   ;"
			"DID_SDID={0xdd,0xDD}  ;  "
			"DID_SDID={0xee,0xEE};; ;\n";

	struct smpte2110_40_fmtp_validator_info fv1 = { { { 0xaa, 0xaa },
			{ 0xbb, 0xbb }, { 0xcc, 0xcc }, { 0xdd, 0xdd },
			{ 0xee, 0xee } }, 0 };
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_rtpmap, 100, "smpte291", 90000, "");
	SET_ATTR_VINFO(0, 1, smpte2110_40_fmtp, &fv1);
	return test_generic(content, SDP_PARSE_OK, assert_session, smpte2110);
}

REG_TEST(test_smpte_40_9, "FAIL - smpte2110 one VPID_Code bad format 1.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 9\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 VPID_Code\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_smpte_40_10, "FAIL - smpte2110 one VPID_Code bad format 2.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 10\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 VPID_Code=\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_smpte_40_11, "FAIL - smpte2110 one VPID_Code bad format 3.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 11\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 VPID_Code=xxx\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_smpte_40_12, "PASS - smpte2110 one VPID_Code valid.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 12\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 "
			"DID_SDID={0xaa,0xAA};"
			"VPID_Code=123;"
			"DID_SDID={0xaa,0xAA};\n";

	struct smpte2110_40_fmtp_validator_info fv1 = { { { 0xaa, 0xaa },
			{ 0xaa, 0xaa } }, 123 };
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_rtpmap, 100, "smpte291", 90000, "");
	SET_ATTR_VINFO(0, 1, smpte2110_40_fmtp, &fv1);
	return test_generic(content, SDP_PARSE_OK, assert_session, smpte2110);
}

REG_TEST(test_smpte_40_13, "FAIL - smpte2110 multiple VPID_Codes.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 40 13\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=fmtp:100 "
			"DID_SDID={0xaa,0xAA};"
			"VPID_Code=123;"
			"DID_SDID={0xaa,0xAA};"
			"VPID_Code=456\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

/******************************************************************************
                               Groups and Mids
******************************************************************************/
REG_TEST(test_mid_1, "FAIL - smpte2110 mid missing value.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test mid 1\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=mid:\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_groups_1, "FAIL - group with no tags.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 1\n"
		"t=0 0\n"
		"a=group:DUP";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_groups_2,
		"PASS - group exits, but some medias have no mids.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 2\n"
		"t=0 0\n"
		"a=group:DUP 1\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:1\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:2\n"
		"m=audio 50000 RTP/AVP 0\n";
	return test_generic(content, SDP_PARSE_OK, NULL, no_specific);
}

REG_TEST(test_groups_3, "PASS - group with no found medias (warning).")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 3\n"
		"t=0 0\n"
		"a=group:DUP 4\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:1\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:2\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:3\n";
	return test_generic(content, SDP_PARSE_OK, NULL, no_specific);
}

REG_TEST(test_groups_4, "FAIL - media with more than one mid.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 4\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:2\n"
		"a=mid:3\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_groups_5, "PASS - group with some met medias but not all.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 5\n"
		"t=0 0\n"
		"a=group:DUP 1 2 3 4\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:2\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:3\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:1\n";
	struct group_validator_info gvi0 =
		{ "DUP", 4, { { "1", 3 }, { "2", 1 }, { "3", 2 },
		{ "4", -1 } } };

	init_session_validator();
	SET_ATTR_VINFO(-1, 0, no_specific_group, &gvi0);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_groups_6, "FAIL - 2 groups, medias already used.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 6\n"
		"t=0 0\n"
		"a=group:DUPA 1 2 3 4\n"
		"a=group:DUPB 1 2 3 4\n"
		"m=audio 50000 RTP/AVP 0\na=mid:4\n"
		"m=audio 50000 RTP/AVP 0\na=mid:3\n"
		"m=audio 50000 RTP/AVP 0\na=mid:2\n"
		"m=audio 50000 RTP/AVP 0\na=mid:1\n";
	struct group_validator_info gvi0 =
		{ "DUPA", 4, { { "1", 3 }, { "2", 2 }, { "3", 1 },
		{ "4", 0 } } };
	struct group_validator_info gvi1 =
		{ "DUPB", 4, { { "1", -1 }, { "2", -1 }, { "3", -1 },
		{ "4", -1 } } };

	init_session_validator();
	SET_ATTR_VINFO(-1, 0, no_specific_group, &gvi0);
	SET_ATTR_VINFO(-1, 1, no_specific_group, &gvi1);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_groups_7, "FAIL - 2 groups, medias already used (2).")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 7\n"
		"t=0 0\n"
		"a=group:DUP 1 2 3 4\n"
		"m=audio 50000 RTP/AVP 0\na=mid:4\n"
		"m=audio 50000 RTP/AVP 0\na=mid:3\n"
		"a=group:DUP 1 2\n"
		"m=audio 50000 RTP/AVP 0\na=mid:2\n"
		"m=audio 50000 RTP/AVP 0\na=mid:1\n";
	struct group_validator_info gvi0 =
		{ "DUP", 4, { { "1", 3 }, { "2", 2 }, { "3", 1 },
		{ "4", 0 } } };
	struct group_validator_info gvi1 =
		{ "DUP", 2, { { "1", -1 }, { "2", -1 } } };

	init_session_validator();
	SET_ATTR_VINFO(-1, 0, no_specific_group, &gvi0);
	SET_ATTR_VINFO(-1, 1, no_specific_group, &gvi1);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_groups_8, "PASS - medias right after groups.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 8\n"
		"t=0 0\n"
		"a=group:DUPA 1 2\n"
		"m=audio 50000 RTP/AVP 0\na=mid:1\n"
		"m=audio 50000 RTP/AVP 0\na=mid:2\n"
		"a=group:DUPB 1 2\n"
		"m=audio 50000 RTP/AVP 0\na=mid:1\n"
		"m=audio 50000 RTP/AVP 0\na=mid:2\n"
		"a=group:DUPC 1 2\n"
		"m=audio 50000 RTP/AVP 0\na=mid:1\n"
		"m=audio 50000 RTP/AVP 0\na=mid:2\n"
		"a=group:DUPD 1 2\n"
		"m=audio 50000 RTP/AVP 0\na=mid:1\n"
		"m=audio 50000 RTP/AVP 0\na=mid:2\n";
	struct group_validator_info gvi0 =
		{ "DUPA", 2, { { "1", 0 }, { "2", 1 } } };
	struct group_validator_info gvi1 =
		{ "DUPB", 2, { { "1", 2 }, { "2", 3 } } };
	struct group_validator_info gvi2 =
		{ "DUPC", 2, { { "1", 4 }, { "2", 5 } } };
	struct group_validator_info gvi3 =
		{ "DUPD", 2, { { "1", 6 }, { "2", 7 } } };

	init_session_validator();
	SET_ATTR_VINFO(-1, 0, no_specific_group, &gvi0);
	SET_ATTR_VINFO(-1, 1, no_specific_group, &gvi1);
	SET_ATTR_VINFO(-1, 2, no_specific_group, &gvi2);
	SET_ATTR_VINFO(-1, 3, no_specific_group, &gvi3);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_groups_9, "PASS - groups before medias.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 9\n"
		"t=0 0\n"
		"a=group:DUPA 3 4\n"
		"a=group:DUPB 3 4\n"
		"a=group:DUPC 3 4\n"
		"a=group:DUPD 3 4\n"
		"m=audio 50000 RTP/AVP 0\na=mid:3\n"
		"m=audio 50000 RTP/AVP 0\na=mid:4\n"
		"m=audio 50000 RTP/AVP 0\na=mid:3\n"
		"m=audio 50000 RTP/AVP 0\na=mid:4\n"
		"m=audio 50000 RTP/AVP 0\na=mid:3\n"
		"m=audio 50000 RTP/AVP 0\na=mid:4\n"
		"m=audio 50000 RTP/AVP 0\na=mid:3\n"
		"m=audio 50000 RTP/AVP 0\na=mid:4\n";
	struct group_validator_info gvi0 =
		{ "DUPA", 2, { { "3", 0 }, { "4", 1 } } };
	struct group_validator_info gvi1 =
		{ "DUPB", 2, { { "3", 2 }, { "4", 3 } } };
	struct group_validator_info gvi2 =
		{ "DUPC", 2, { { "3", 4 }, { "4", 5 } } };
	struct group_validator_info gvi3 =
		{ "DUPD", 2, { { "3", 6 }, { "4", 7 } } };

	init_session_validator();
	SET_ATTR_VINFO(-1, 0, no_specific_group, &gvi0);
	SET_ATTR_VINFO(-1, 1, no_specific_group, &gvi1);
	SET_ATTR_VINFO(-1, 2, no_specific_group, &gvi2);
	SET_ATTR_VINFO(-1, 3, no_specific_group, &gvi3);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_groups_10, "PASS - groups after medias.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 10\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:5\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:5\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:5\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:5\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n"
		"a=group:DUPA 5 6\n"
		"a=group:DUPB 5 6\n"
		"a=group:DUPC 5 6\n"
		"a=group:DUPD 5 6\n";
	struct group_validator_info gvi0 =
		{ "DUPA", 2, { { "5", 0 }, { "6", 1 } } };
	struct group_validator_info gvi1 =
		{ "DUPB", 2, { { "5", 2 }, { "6", 3 } } };
	struct group_validator_info gvi2 =
		{ "DUPC", 2, { { "5", 4 }, { "6", 5 } } };
	struct group_validator_info gvi3 =
		{ "DUPD", 2, { { "5", 6 }, { "6", 7 } } };

	init_session_validator();
	SET_ATTR_VINFO(-1, 0, no_specific_group, &gvi0);
	SET_ATTR_VINFO(-1, 1, no_specific_group, &gvi1);
	SET_ATTR_VINFO(-1, 2, no_specific_group, &gvi2);
	SET_ATTR_VINFO(-1, 3, no_specific_group, &gvi3);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_groups_11, "PASS - groups swap.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 11\n"
		"t=0 0\n"
		"a=group:DUPA 7 8\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:14\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:13\n"
		"a=group:DUPB 9 10\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:12\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:11\n"
		"a=group:DUPC 11 12\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:10\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:9\n"
		"a=group:DUPD 13 14\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:8\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:7\n";
	struct group_validator_info gvi0 =
		{ "DUPA", 2, { { "7",  7 }, { "8",  6 } } };
	struct group_validator_info gvi1 =
		{ "DUPB", 2, { { "9",  5 }, { "10", 4 } } };
	struct group_validator_info gvi2 =
		{ "DUPC", 2, { { "11", 3 }, { "12", 2 } } };
	struct group_validator_info gvi3 =
		{ "DUPD", 2, { { "13", 1 }, { "14", 0 } } };

	init_session_validator();
	SET_ATTR_VINFO(-1, 0, no_specific_group, &gvi0);
	SET_ATTR_VINFO(-1, 1, no_specific_group, &gvi1);
	SET_ATTR_VINFO(-1, 2, no_specific_group, &gvi2);
	SET_ATTR_VINFO(-1, 3, no_specific_group, &gvi3);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

REG_TEST(test_groups_12, "PASS - all combined.")
{
	char *content =
		"v=0\n"
		"s=SDP test: test groups 12\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:5\n" /*  0 - A */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n" /*  1 - A */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:5\n" /*  2 - B */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n" /*  3 - B */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:5\n" /*  4 - C */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n" /*  5 - C */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:5\n" /*  6 - D */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:6\n" /*  7 - D */
		"a=group:DUPA 1 2 3 4 5 6 7 8\n" /* Medias: 10 11 24 25 0 1 
						    21 20 */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:14\n" /*  8 - D */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:13\n" /*  9 - D */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:1\n" /*  10 - A */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:2\n" /*  11 - A */
		"a=group:DUPB 1 2 3 4 5 6 9 10\n" /* Medias: 14 15 26 27 2 3 17
						     16 */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:12\n" /* 12 - C */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:11\n" /* 13 - C */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:1\n" /*  14 - B */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:2\n" /*  15 - B */
		"a=group:DUPC 1 2 3 4 5 6 11 12\n" /* Medias: 18 19 28 29 4 5 13
						      12 */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:10\n" /* 16 - B */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:9\n" /*  17 - B */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:1\n" /*  18 - C */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:2\n" /*  19 - C */
		"a=group:DUPD 1 2 3 4 5 6 13 14\n" /* Medias: 22 23 30 31 6 7 9
						      8 */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:8\n" /*  20 - A */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:7\n" /*  21 - A */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:1\n" /*  22 - D */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:2\n" /*  23 - D */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:3\n" /* 24 - A */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:4\n" /* 25 - A */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:3\n" /* 26 - B */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:4\n" /* 27 - B */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:3\n" /* 28 - C */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:4\n" /* 29 - C */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:3\n" /* 30 - D */
		"m=audio 50000 RTP/AVP 0\n"
		"a=mid:4\n" /* 31 - D */;
	/* Medias: 10 11 27 26 0 1 21 20 */
	struct group_validator_info gvi0 = { "DUPA", 8,
		{ { "1", 10 }, { "2", 11 }, { "3", 24 }, { "4", 25 },
		{ "5", 0  }, { "6", 1  }, { "7", 21 }, { "8", 20 } } };
	/* Medias: 14 15 29 28 2 3 17 16 */
	struct group_validator_info gvi1 = { "DUPB", 8,
		{ { "1", 14 }, { "2", 15 }, { "3", 26 }, { "4", 27 },
		{ "5", 2  }, { "6", 3  }, { "9", 17 }, { "10",16 } } };
	/* Medias: 18 19 31 30 4 5 13 12 */
	struct group_validator_info gvi2 = { "DUPC", 8,
		{ { "1", 18 }, { "2", 19 }, { "3", 28 }, { "4", 29 },
		{ "5", 4  }, { "6", 5  }, { "11",13 }, { "12",12 } } };
	/* Medias: 22 23 25 24 6 7 9 8 */
	struct group_validator_info gvi3 = { "DUPD", 8,
		{ { "1", 22 }, { "2", 23 }, { "3", 30 }, { "4", 31 },
		{ "5", 6  }, { "6", 7  }, { "13",9  }, { "14",8  } } };

	init_session_validator();
	SET_ATTR_VINFO(-1, 0, no_specific_group, &gvi0);
	SET_ATTR_VINFO(-1, 1, no_specific_group, &gvi1);
	SET_ATTR_VINFO(-1, 2, no_specific_group, &gvi2);
	SET_ATTR_VINFO(-1, 3, no_specific_group, &gvi3);
	return test_generic(content, SDP_PARSE_OK, assert_session, no_specific);
}

/******************************************************************************
                                Smpte2022-6
******************************************************************************/
REG_TEST(test_smpte_2022_6_1, "FAIL - smpte2022-6 invalid sub-type.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 2022-6 1\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 raw/90000\n";
	return test_generic(content, SDP_PARSE_NOT_SUPPORTED, NULL, smpte2022);
}

REG_TEST(test_smpte_2022_6_2, "PASS - smpte2022-6.")
{
	char *content =
		"v=0\n"
		"s=SDP test: smpte 2022-6 2\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 100\n"
		"a=rtpmap:100 smpte2022-6/90000\n"
		"a=framerate:99.99\n";

	init_session_validator();
	validator_info.medias[0].formats[0].id = 100;
	validator_info.medias[0].formats[0].sub_type = SMPTE_2022_SUB_TYPE_6;
	SET_ATTR_VINFO(0, 0, no_specific_rtpmap, 100, "smpte2022-6", 90000, "");
	SET_ATTR_VINFO(0, 1, no_specific_framerate, 99.99);
	return test_generic(content, SDP_PARSE_OK, assert_session, smpte2022);
}

/******************************************************************************
                                 Test Table
******************************************************************************/
void init_tests()
{
	ADD_TEST(test001);
	ADD_TEST(test002);
	ADD_TEST(test003);
	ADD_TEST(test004);
	ADD_TEST(test005);
	ADD_TEST(test006);
	ADD_TEST(test007);
	ADD_TEST(test008);
	ADD_TEST(test009);
	ADD_TEST(test010);
	ADD_TEST(test011);
	ADD_TEST(test012);
	ADD_TEST(test013);
	ADD_TEST(test014);
	ADD_TEST(test015);
	ADD_TEST(test016);
	ADD_TEST(test017);
	ADD_TEST(test018);
	ADD_TEST(test019);
	ADD_TEST(test020);
	ADD_TEST(test021);
	ADD_TEST(test022);
	ADD_TEST(test023);
	ADD_TEST(test024);
	ADD_TEST(test025);
	ADD_TEST(smpte2110_sub_types_1);
	ADD_TEST(smpte2110_sub_types_2);
	ADD_TEST(smpte2110_sub_types_3);
	ADD_TEST(smpte2110_sub_types_4);
	ADD_TEST(smpte2110_sub_types_5);
	ADD_TEST(test_rtpmap_payload_type_1);
	ADD_TEST(test_rtpmap_payload_type_2);
	ADD_TEST(test_rtpmap_payload_type_3);
	ADD_TEST(test_rtpmap_payload_type_4);
	ADD_TEST(test_rtpmap_payload_type_5);
	ADD_TEST(test_rtpmap_encoding_name_1);
	ADD_TEST(test_rtpmap_bit_depth_1);
	ADD_TEST(test_rtpmap_bit_depth_2);
	ADD_TEST(test_rtpmap_clock_rate_1);
	ADD_TEST(test_rtpmap_clock_rate_2);
	ADD_TEST(test_rtpmap_clock_rate_3);
	ADD_TEST(test_rtpmap_num_channels_1);
	ADD_TEST(test_rtpmap_num_channels_2);
	ADD_TEST(test_rtpmap_num_channels_3);
	ADD_TEST(test_rtpmap_num_channels_4);
	ADD_TEST(test_rtpmap_num_channels_5);
	ADD_TEST(test_ptime_1);
	ADD_TEST(test_ptime_2);
	ADD_TEST(test_ptime_3);
	ADD_TEST(test_ptime_4);
	ADD_TEST(test_ptime_5);
	ADD_TEST(test_framerate_1);
	ADD_TEST(test_framerate_2);
	ADD_TEST(test_framerate_3);
	ADD_TEST(test_framerate_4);
	ADD_TEST(test_mid_1);
	ADD_TEST(test_smpte_40_1);
	ADD_TEST(test_smpte_40_2);
	ADD_TEST(test_smpte_40_3);
	ADD_TEST(test_smpte_40_4);
	ADD_TEST(test_smpte_40_5);
	ADD_TEST(test_smpte_40_6);
	ADD_TEST(test_smpte_40_7);
	ADD_TEST(test_smpte_40_8);
	ADD_TEST(test_smpte_40_9);
	ADD_TEST(test_smpte_40_10);
	ADD_TEST(test_smpte_40_11);
	ADD_TEST(test_smpte_40_12);
	ADD_TEST(test_smpte_40_13);
	ADD_TEST(test_smpte_2022_6_1);
	ADD_TEST(test_smpte_2022_6_2);
	ADD_TEST(test_groups_1);
	ADD_TEST(test_groups_2);
	ADD_TEST(test_groups_3);
	ADD_TEST(test_groups_4);
	ADD_TEST(test_groups_5);
	ADD_TEST(test_groups_6);
	ADD_TEST(test_groups_7);
	ADD_TEST(test_groups_8);
	ADD_TEST(test_groups_9);
	ADD_TEST(test_groups_10);
	ADD_TEST(test_groups_11);
	ADD_TEST(test_groups_12);
}

