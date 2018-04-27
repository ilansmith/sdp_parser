#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "sdp_parser.h"
#include "smpte2110_sdp_parser.h"
#include "unit_test.h"

static void tmpfile_close(int fd, char *path)
{
	close(fd);
	unlink(path);
}

static int tmpfile_open(char *content, char **ptr)
{
	static char name[11];
	int fd;
	int len;
	int ret;

	snprintf(name, ARRAY_SZ(name), "sdp_XXXXXX");
	fd = mkstemp(name);
	if (fd == -1) {
		char *err;

		switch (errno) {
		case EEXIST:
			err = "Could not create a unique temporary filename.";
			break;
		case EINVAL:
			err = "The last six characters of template were not "
				"XXXXXX;";
			break;
		default:
			err = "Unknown error.";
			break;
		}

		fprintf(stderr, "%s(): %s\n", __FUNCTION__, err);
		return -1;
	}

	len = strlen(content);
	ret = write(fd, content, len);
	if (ret != len) {
		printf("%s(): Error writing content to temp file.\n",
			__FUNCTION__);
		tmpfile_close(fd, name);
	}

	*ptr = name;
	return fd;
}

static int test_generic(char *content, enum sdp_parse_err expected,
		int (*verifier)(struct sdp_session *session))
{
	int ret = -1;
	int sdp;
	char *path;
	enum sdp_parse_err err;
	struct sdp_session *session;

	sdp = tmpfile_open(content, &path);
	if (sdp == -1)
		goto exit;

	session = sdp_parser_init(SDP_STREAM_TYPE_FILE, path);
	if (!session) {
		printf("failed to parse sdp session\n");
		goto exit;
	}

	err = sdp_session_parse(session, smpte2110_sdp_parse_specific);
	if (err == expected)
		ret = (!verifier || !verifier(session)) ? 0 : -1;

	sdp_parser_uninit(session);

exit:
	if (sdp != -1)
		tmpfile_close(sdp, path);

	return ret;

}

static int test_generic_get_error(char *content, enum sdp_parse_err expected)
{
	return test_generic(content, expected, NULL);
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

	return test_generic_get_error(content, SDP_PARSE_ERROR);
}

static int test001(void)
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

	return test_generic_get_error(content, SDP_PARSE_OK);
}

static int test002(void)
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

	return test_generic_get_error(content, SDP_PARSE_OK);
}

static int test003(void)
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

	return test_generic_get_error(content, SDP_PARSE_ERROR);
}

static int test004(void)
{
	char *content =
		"v=0\n";

	return test_generic_get_error(content, SDP_PARSE_ERROR);
}

static int test005(void)
{
	char *content =
		"v=0\n"
		"o=- 123456 11 IN IP4 192.168.100.2\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"i=this example is for 720p video at 59.94\n"
		"t=0 0\n"
		"a=recvonly\n"
		"a=group:DUP primary secondary\n";

	return test_generic_get_error(content, SDP_PARSE_OK);
}

static int test006(void)
{
	char *content =
		"v=0\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"m=video 50000 RTP/AVP 112\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017;\n";

	return test_generic_get_error(content, SDP_PARSE_OK);
}

static int test007(void)
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

	return test_generic_get_error(content, SDP_PARSE_OK);
}

static int test008(void)
{
	return missing_required_fmtp_param(SMPTE_ERR_SAMPLING);
}

static int test009(void)
{
	return missing_required_fmtp_param(SMPTE_ERR_DEPTH);
}

static int test010(void)
{
	return missing_required_fmtp_param(SMPTE_ERR_WIDTH);
}

static int test011(void)
{
	return missing_required_fmtp_param(SMPTE_ERR_HEIGHT);
}

static int test012(void)
{
	return missing_required_fmtp_param(SMPTE_ERR_EXACTFRAMERATE);
}

static int test013(void)
{
	return missing_required_fmtp_param(SMPTE_ERR_COLORIMETRY);
}

static int test014(void)
{
	return missing_required_fmtp_param(SMPTE_ERR_PM);
}

static int test015(void)
{
	return missing_required_fmtp_param(SMPTE_ERR_TP);
}

static int test016(void)
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
			printf("%s(): excess media clauses\n", __FUNCTION__);
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
					.dst_addr = "239.100.9.10",
					.src_addr = "192.168.100.2"
				},
				{
					.dst_addr = "239.101.9.10",
					.src_addr = "192.168.101.2"
				}
			};

			if (0 < cnt_a) {
				printf("%s(): excess source-filter "
					"attributes\n", __FUNCTION__);
				return -1;
			}

			/* assert attribute type */
			if (attr->type != SDP_ATTR_SOURCE_FILTER) {
				printf("%s(): bad attr type: %d\n",
					__FUNCTION__, attr->type);
				return -1;
			}

			source_filter = &attr->value.source_filter;

			/* assert source-filter mode */
			if (source_filter->mode != SDP_ATTR_SRC_FLT_INCL) {
				printf("%s(): bad source-filter mode: %d\n",
					__FUNCTION__, source_filter->mode);
				return -1;
			}

			/* assert source-filter net type */
			if (source_filter->spec.nettype != SDP_CI_NETTYPE_IN) {
				printf("%s(): bad source-filter nettype: %d\n",
					__FUNCTION__,
					source_filter->spec.nettype);
				return -1;
			}

			/* assert source-filter addr type */
			if (source_filter->spec.addrtype !=
					SDP_CI_ADDRTYPE_IPV4) {
				printf("%s(): bad source-filter addrtype: %d\n",
					__FUNCTION__,
					source_filter->spec.addrtype);
				return -1;
			}

			/* assert source-filter dst addr */
			if (strncmp(addresses[cnt_m].dst_addr,
					source_filter->spec.dst_addr,
					sizeof(source_filter->spec.dst_addr))) {
				printf("%s(): bad source-filter dst-addr: %s\n",
					__FUNCTION__,
					source_filter->spec.dst_addr);
				return -1;
			}

			/* assert source-filter src addr */
			if (strncmp(addresses[cnt_m].src_addr,
					source_filter->spec.src_list.addr,
					sizeof(
					source_filter->spec.src_list.addr))) {
				printf("%s(): bad source-filter src-addr: %s\n",
					__FUNCTION__,
					source_filter->spec.src_list.addr);
				return -1;
			}

			/* assert source-filter has a single src addr */
			if (source_filter->spec.src_list.next) {
				printf("%s() bad source_filter src_list.next "
					"pointer: %p\n", __FUNCTION__,
					source_filter->spec.src_list.next);
				return -1;
			}

			/* assert source-filter has a single src addr */
			if (source_filter->spec.src_list_len != 1) {
				printf("%s() bad source_filter src_list_len: "
					"%d", __FUNCTION__,
					source_filter->spec.src_list_len);
				return -1;
			}

		}

		if (cnt_a != 1) {
			printf("%s() Wrong number of source-filter attributes: "
				"%d\n", __FUNCTION__, cnt_a);
			return -1;
		}
	}

	if (cnt_m != 2) {
		printf("%s() Wrong number of media clauses: %d\n", __FUNCTION__,
			cnt_m);
		return -1;
	}

	return 0;
}

static int test017(void)
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

	return test_generic(content, SDP_PARSE_OK, assert_source_filter);
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
			printf("%s(): excess media clauses\n", __FUNCTION__);
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
				printf("%s(): excess media stream "
					"identification attributes\n",
					__FUNCTION__);
				return -1;
			}

			/* assert attribute type */
			if (attr->type != SDP_ATTR_MID) {
				printf("%s(): bad attr type: %d\n",
					__FUNCTION__, attr->type);
				return -1;
			}

			mid = &attr->value.mid;

			/* assert identification tag */
			if (strncmp(mid->identification_tag,
					identification_tag[cnt_m],
					strlen(mid->identification_tag))) {
				printf("%s(): bad identification tag: %s\n",
					__FUNCTION__, mid->identification_tag);
				return -1;
			}

		}

		if (cnt_a != 1) {
			printf("%s() Wrong number of media steram "
				"identification attributes: %d\n", __FUNCTION__,
				cnt_a);
			return -1;
		}
	}

	if (cnt_m != 2) {
		printf("%s() Wrong number of media clauses: %d\n", __FUNCTION__,
			cnt_m);
		return -1;
	}

	return 0;
}

static int test018(void)
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

	return test_generic(content, SDP_PARSE_OK, assert_mid);
}

static int assert_group(struct sdp_session *session)
{
	struct sdp_attr *attr;
	int cnt_a;

	/* loop over all a=group blocks (should be only one) */
	for (attr = sdp_session_attr_get(session, SDP_ATTR_GROUP), cnt_a = 0;
			attr; attr = sdp_attr_get_next(attr), cnt_a++) {
		struct sdp_attr_value_group *group;
		struct group_member *member;
		char *identification_tag[2] = {
			"primary", "secondary"
		};
		int i;

		if (0 < cnt_a) {
			printf("%s(): excess media stream group attributes\n",
				__FUNCTION__);
			return -1;
		}

		/* assert attribute type */
		if (attr->type != SDP_ATTR_GROUP) {
			printf("%s(): bad attr type: %d\n", __FUNCTION__,
				attr->type);
			return -1;
		}

		group = &attr->value.group;

		/* assert that group semantic is "DUP" */
		if (strncmp(group->semantic, "DUP", strlen("DUP"))) {
			printf("%s(): bad group semantic: %s\n", __FUNCTION__,
				group->semantic);
			return -1;
		}

		/* assert that number of tags in group is 2 */
		if (group->num_tags != 2) {
			printf("%s(): bad number of tags: %d\n", __FUNCTION__,
				group->num_tags);
			return -1;
		}

		/* assert group identification tags */
		for (member = group->member, i = 0;
				member && i < group->num_tags;
				member = member->next, i++) {
			if (strncmp(member->identification_tag,
					identification_tag[i],
					strlen(identification_tag[i]))) {
				printf("%s(): bad group identification tag: "
					"%s\n", __FUNCTION__,
					member->identification_tag);
				return -1;
			}
		}

		/* assert that there are no excess tags */
		if (member) {
			printf("%s(): last group identification tag points to "
				"dangling location: %p", __FUNCTION__, member);
			return -1;
		}
	}

	/* assert a single media group attribute */
	if (cnt_a != 1) {
		printf("%s() Wrong number of media steram group attributes: "
			"attributes: %d\n", __FUNCTION__, cnt_a);
		return -1;
	}

	return 0;
}

static int assert_no_group(struct sdp_session *session)
{
	struct sdp_attr *attr;

	attr = sdp_session_attr_get(session, SDP_ATTR_GROUP);
	if (attr) {
		printf("%s(): found non existing media group identification\n",
			__FUNCTION__);
		return -1;
	}

	return 0;
}

static int test019(void)
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

	return test_generic(content, SDP_PARSE_OK, assert_group);
}

static int test020(void)
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

	return test_generic(content, SDP_PARSE_OK, assert_no_group);
}

static int test021(void)
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

	return test_generic_get_error(content, SDP_PARSE_OK);
}

static int test022(void)
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
		"a=mid:VID1\n"
		"m=audio 5010 RTP/AVP 110\n"
		"c=IN IPV4 239.10.10.110/96\n"
		"a=rtpmap:100 L24/48000/2\n"
		"a=fmtp:100 channel-order=SMPTE2110.(ST)\n"
		"a=ptime:1.000\n"
		"a=tsrefclk:ptp=IEEE1588-2008:08-00-11-FF-FE-22-39-E4:125\n"
		"a=mediaclk:direct=0\n"
		"a=mid:AUD\n"
		"m=video 5050 RTP/AVP 97\n"
		"c=IN IP4 239.10.10.97/96\n"
		"a=rtpmap:97 raw/90000\n"
		"a=fmtp:97 sampling=YCbCr-4:2:2; width=1920; height=1080; "
			"exactframerate=30000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110BPM; "
			"SSN=\"ST2110-20:2017\"; interlace; TP=2110TPN\n"
		"a=tsrefclk:ptp=IEEE1588-2008:08-00-11-FF-FE-22-39-E4:125\n"
		"a=mediaclk:direct=0\n"
		"a=mid:VID2\n";

	return test_generic_get_error(content, SDP_PARSE_OK);
}

static struct single_test sdp_tests[] = {
	{
		description: "SMPTE2110-10 annex B example SDP",
		func: test001,
	},
	{
		description: "Minimum supported set",
		func: test002,
	},
	{
		description: "Fail on missing required v=",
		func: test003,
	},
	{
		description: "Fail on nothing beyond v=",
		func: test004,
	},
	{
		description: "Allow no m=",
		func: test005,
	},
	{
		description: "Parse v=, m= and a=fmtp:<fmt> only",
		func: test006,
	},
	{
		description: "a=fmtp: pass on missing default parameters",
		func: test007,
	},
	{
		description: "a=fmtp: fail on missing required sampling=",
		func: test008,
	},
	{
		description: "a=fmtp: fail on missing required depth=",
		func: test009,
	},
	{
		description: "a=fmtp: fail on missing required width=",
		func: test010,
	},
	{
		description: "a=fmtp: fail on missing required height=",
		func: test011,
	},
	{
		description: "a=fmtp: fail on missing required exactframerate=",
		func: test012,
	},
	{
		description: "a=fmtp: fail on missing required colorimetry=",
		func: test013,
	},
	{
		description: "a=fmtp: fail on missing required PM=",
		func: test014,
	},
	{
		description: "a=fmtp: fail on missing required TP=",
		func: test015,
	},
	{
		description: "a=fmtp: fail on missing required SSN=",
		func: test016,
	},
	{
		description: "a=source-filter: <filter-mode> <filter-spec>",
		func: test017,
	},
	{
		description: "a=mid: <identification_tag>",
		func: test018,
	},
	{
		description: "a=group:DUP <primary> <secondary>",
		func: test019,
	},
	{
		description: "Identify no a=group attribute",
		func: test020,
	},
	{
		description: "SSN quoted value",
		func: test021,
	},
	{
		description: "a=fmtp for non raw video format",
		func: test022,
	},
};

struct unit_test ut_sdp = {
	.module = "sdp",
	.description = "SMPTE ST-2110 Session Description Protocol",
	.tests = sdp_tests,
	.count = ARRAY_SZ(sdp_tests),
};

