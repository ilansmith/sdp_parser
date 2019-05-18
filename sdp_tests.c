/*
 * comp_tests.c
 *
 *  Created on: May 3, 2018
 *      Author: eladw
 */

#include <stdlib.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#if defined(__linux__)
#include <errno.h>
#include <unistd.h>
#endif

#include "sdp_stream.h"
#include "sdp_parser.h"
#include "smpte2110_sdp_parser.h"

#define C_RED    "\033[00;31m"
#define C_GREEN  "\033[00;32m"
#define C_YELLOW "\033[00;33m"
#define C_ITALIC "\033[00;03m"
#define C_NORMAL "\033[00;00;00m"

#ifndef ARRAY_SZ
#define ARRAY_SZ(array) (int)(sizeof(array) / sizeof(array[0]))
#endif

typedef void (*sdp_attr_func_ptr)(void);
typedef int (*test_func)(void);

struct single_test
{
	const char *name;
	const char *description;
	test_func func;
};

#define MAX_NUM_TESTS 300
static struct single_test tests[MAX_NUM_TESTS];
static int num_tests = 0;

void add_test(test_func func, const char *name, const char *description)
{
	int id = num_tests++;
	tests[id].name = name;
	tests[id].description = description;
	tests[id].func = func;
}

#define REG_TEST(_name_, _summary_) \
	static const char *_name_ ## _summary = _summary_; \
	static int _name_(void)

#define ADD_TEST(_name_) add_test(_name_, #_name_, _name_ ## _summary)

static int test_log(const char *format, ...)
{
	va_list va;
	va_start(va, format);
	fprintf(stderr, "#### ");
	vfprintf(stderr, format, va);
	va_end(va);
	return 0;
}

static int assert_error(const char *format, ...)
{
	va_list va;
	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);
	return 0;
}

int vprint_title(const char *format, va_list va)
{
   int uiIt;
   char title[256];
   char line_buf[256], *ptr = line_buf;
   int uiLen = vsprintf(title, format, va);
   //test_log("┏━");
   ptr += sprintf(ptr, "+-");
   for ( uiIt = 0; uiIt < uiLen; uiIt++ )
   {
      //test_log("━" );
      ptr += sprintf(ptr, "-" );
   }
   //test_log("━┓\n" );
   //test_log("┃ %s ┃\n", title);
   //test_log("┗━" );
   ptr += sprintf(ptr, "-+\n" );
   test_log("%s", line_buf);

   test_log("| %s |\n", title);

   ptr = line_buf;
   ptr += sprintf(ptr, "+-");
   for ( uiIt = 0; uiIt < uiLen; uiIt++ )
   {
      //test_log("━" );
	   ptr += sprintf(ptr, "-");
   }
   //test_log("━┛\n" );
   ptr += sprintf(ptr, "-+\n" );
   test_log("%s", line_buf);
   return uiLen + 4;
}

int print_title(const char* format, ...)
{
   va_list va;
   int ret;
   va_start(va, format);
   ret = vprint_title(format, va);
   va_end(va);
   return ret;
}

struct test_ctx {
	enum sdp_stream_type type;
	union {
		struct {
			int fd;
			char *path;
		} file;
		char *buf;
	} data;
	struct sdp_session *session;
};

#if defined(__linux__)
static void tmpfile_close(struct test_ctx *ctx)
{
	if (ctx->data.file.fd == -1)
		return;

	close(ctx->data.file.fd);
	unlink(ctx->data.file.path);
}

static int tmpfile_open(const char *content, struct test_ctx *ctx)
{
	static char name[11];
	int fd;
	int len;
	int ret;

	snprintf(name, 11, "sdp_XXXXXX");
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

		fprintf(stderr, "%s(): %s\n", __func__, err);
		return -1;
	}

	len = strlen(content);
	ret = write(fd, content, len);
	if (ret != len) {
		test_log("%s(): Error writing content to temp file.\n",
			__func__);
		close(fd);
		unlink(name);
		return -1;
	}

	ctx->data.file.fd = fd;
	ctx->data.file.path = name;
	return 0;
}
#else
#define tmpfile_close(_ctx_)
#define tmpfile_open(_content_, _ctx_) 1
#endif

static void tmpbuf_uninit(struct test_ctx *ctx)
{
	if (ctx->data.buf) {
		memset(ctx->data.buf, 0, strlen(ctx->data.buf));
		free(ctx->data.buf);
	}
}

static int tmpbuf_init(const char *content, struct test_ctx *ctx)
{
	int len = strlen(content);
	char *tmp;

	tmp = (char*)calloc(len + 1, 1);
	if (!tmp)
		return -1;

	strncpy(tmp, content, len);

	ctx->data.buf = tmp;
	return 0;
}

static void generic_context_uninit(struct test_ctx *ctx)
{
	if (ctx->session)
		sdp_parser_uninit(ctx->session);

	switch (ctx->type) {
	case SDP_STREAM_TYPE_FILE:
		tmpfile_close(ctx);
		break;
	case SDP_STREAM_TYPE_CHAR:
		tmpbuf_uninit(ctx);
		break;
	default:
		break;
	}

	free(ctx);
}

static struct test_ctx *generic_context_init(enum sdp_stream_type type,
		const char *content)
{
	struct test_ctx *ctx;
	int ret = -1;

	ctx = calloc(1, sizeof(struct test_ctx));
	if (!ctx)
		return NULL;

	switch (type) {
	case SDP_STREAM_TYPE_FILE:
		if (tmpfile_open(content, ctx))
			goto exit;

		ctx->session = sdp_parser_init(SDP_STREAM_TYPE_FILE,
			ctx->data.file.path);
		if (!ctx->session) {
			test_log("failed to init sdp session from file\n");
			goto exit;
		}

		ctx->type = SDP_STREAM_TYPE_FILE;
		break;
	case SDP_STREAM_TYPE_CHAR:
		if (tmpbuf_init(content, ctx))
			goto exit;

		ctx->session = sdp_parser_init(SDP_STREAM_TYPE_CHAR,
			ctx->data.buf);
		if (!ctx->session) {
			test_log("failed to init sdp session from buffer\n");
			goto exit;
		}

		ctx->type = SDP_STREAM_TYPE_CHAR;
		break;
	default:
		break;
	}

	ret = 0;

exit:
	if (ret) {
		generic_context_uninit(ctx);
		ctx = NULL;
	}

	return ctx;
}

static int run_test_generic(const char *content, enum sdp_parse_err expected,
		int (*verifier)(struct sdp_session *session),
		enum sdp_stream_type stream_type, parse_attr_specific_t specific)
{
	int ret = -1;
	struct test_ctx *ctx;
	enum sdp_parse_err err;

	ctx = generic_context_init(stream_type, content);
	if (!ctx)
		return -1;

	err = sdp_session_parse(ctx->session, specific);
	if (err == expected)
		ret = (!verifier || !verifier(ctx->session)) ? 0 : -1;

	generic_context_uninit(ctx);
	return ret;

}

static int test_generic(const char *content, enum sdp_parse_err expected,
		int (*verifier)(struct sdp_session *session),
		parse_attr_specific_t specific)
{
	int i;
	int ret;
	struct {
		enum sdp_stream_type type;
		char *name;
	} stream_types[] = {
#if defined(__linux__)
		{ SDP_STREAM_TYPE_FILE, "file" },
#endif
		{ SDP_STREAM_TYPE_CHAR, "memory" },
	};

	for (ret = 0, i = 0; !ret && i < ARRAY_SZ(stream_types); i++) {
		test_log("%s  running %s stream based test%s\n", C_ITALIC,
			stream_types[i].name, C_NORMAL);
		ret = run_test_generic(content, expected, verifier,
			stream_types[i].type, specific);
	}

	return ret;
}

static int test_generic_smpte2110_get_error(const char *content, enum sdp_parse_err expected)
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
                              Common Validators
******************************************************************************/
static int assert_str(const char *left_name, const char *left,
		const char *right_name, const char *right)
{
	if ((!left) && (!right))
		return 1;
	if (!left)
		return assert_error("Assertion failed: %s is NULL.\n", left_name);
	if (!right)
		return assert_error("Assertion failed: %s is NULL.\n", right_name);
	if (strcmp(left, right) != 0)
		return assert_error("Assertion failed: %s ('%s') != %s ('%s').\n", left_name, left, right_name, right);
	return 1;
}

static int assert_int(const char *left_name, long long left,
		const char *right_name, long long right)
{
	if (left != right)
		return assert_error("Assertion failed: %s ('%lld') != %s ('%lld').\n", left_name, left, right_name, right);
	return 1;
}

static inline int assert_flt(const char *left_name, double left,
		const char *right_name, double right)
{
	static const double epsilon = 0.00001;
	if (fabs(left - right) > epsilon)
		return assert_error("Assertion failed: %s ('%lf') != %s ('%lf').\n", left_name, left, right_name, right);
	return 1;
}

static int assert_res(int res, const char *name, const char* file, int line)
{
	if (!res)
		return assert_error("    In: %s:%u: %s\n", file, line, name);
	return 1;
}

#define ASSERT_RES(_res_)           assert_res(_res_, #_res_, __FILE__, __LINE__)
#define ASSERT_STR(_left_, _right_) assert_res(assert_str(#_left_, _left_, #_right_, _right_), "ASSERT_STR(" #_left_ ", " #_right_ ")", __FILE__, __LINE__)
#define ASSERT_INT(_left_, _right_) assert_res(assert_int(#_left_, _left_, #_right_, _right_), "ASSERT_INT(" #_left_ ", " #_right_ ")", __FILE__, __LINE__)
#define ASSERT_FLT(_left_, _right_) assert_res(assert_flt(#_left_, _left_, #_right_, _right_), "ASSERT_FLT(" #_left_ ", " #_right_ ")", __FILE__, __LINE__)

/******************************************************************************
                              Validator Functions
******************************************************************************/
static int no_specific_fmtp(const struct sdp_attr *attr,
		long long fmt, const char *params)
{
	return ASSERT_INT(attr->type, SDP_ATTR_FMTP) &&
	       ASSERT_INT(attr->value.fmtp.fmt, fmt) &&
	       ASSERT_STR(attr->value.fmtp.params.as.as_str, params);
}

static int no_specific_rtpmap(const struct sdp_attr *attr,
		long long payload_type, const char *encoding_name,
		long long clock_rate, const char *encoding_parameters)
{
	return ASSERT_INT(attr->type, SDP_ATTR_RTPMAP) &&
	       ASSERT_INT(attr->value.rtpmap.payload_type, payload_type) &&
	       ASSERT_STR(attr->value.rtpmap.encoding_name.as.as_str, encoding_name) &&
	       ASSERT_INT(attr->value.rtpmap.clock_rate, clock_rate) &&
	       ASSERT_STR(attr->value.rtpmap.encoding_parameters.as.as_str, encoding_parameters);
}

static inline int no_specific_ptime(const struct sdp_attr *attr,
		double packet_time)
{
	return ASSERT_INT(attr->type, SDP_ATTR_PTIME) &&
	       ASSERT_FLT(attr->value.ptime.packet_time, packet_time);
}

static inline int smpte2110_rtpmap(const struct sdp_attr *attr,
		long long payload_type, long long bit_width, long long clock_rate,
		long long num_channels)
{
	return ASSERT_INT(attr->type, SDP_ATTR_RTPMAP) &&
	       ASSERT_INT(attr->value.rtpmap.payload_type, payload_type) &&
	       ASSERT_INT(attr->value.rtpmap.encoding_name.as.as_ll, bit_width) &&
	       ASSERT_INT(attr->value.rtpmap.clock_rate, clock_rate) &&
	       ASSERT_INT(attr->value.rtpmap.encoding_parameters.as.as_ll, num_channels);
}

/******************************************************************************
                                Validator Info
******************************************************************************/
#define IGNORE_VALUE -1
#define MAX_NUM_MEDIA 10
#define MAX_NUM_SESSION_ATTRIBUTES 20
#define MAX_NUM_MEDIA_ATTRIBUTES 20
#define MAX_NUM_ATTRIBUTE_FIELDS 10

struct attr_validator_info
{
	sdp_attr_func_ptr func; /* Indicates validator type */
	interpretable args[MAX_NUM_ATTRIBUTE_FIELDS];
};

struct media_validator_info
{
	int attr_count;
	struct attr_validator_info attributes[MAX_NUM_MEDIA_ATTRIBUTES];
};

struct session_validator_info
{
	int media_count;
	int session_attr_count;
	struct attr_validator_info attributes[MAX_NUM_SESSION_ATTRIBUTES];
	struct media_validator_info medias[MAX_NUM_MEDIA_ATTRIBUTES];
};

static struct session_validator_info validator_info;

void init_session_validator(void)
{
	struct media_validator_info *mv;
	int m_id;
	memset(&validator_info, 0, sizeof(validator_info));
	validator_info.media_count = -1;
	for (m_id = 0; m_id < MAX_NUM_MEDIA_ATTRIBUTES; ++m_id)
	{
		mv = &validator_info.medias[m_id];
		mv->attr_count = -1;
	}
}

int num_args(sdp_attr_func_ptr func) {
	int num_args = 0;
	if (func == (sdp_attr_func_ptr)no_specific_fmtp)
		num_args = 2;
	else if (func == (sdp_attr_func_ptr)no_specific_rtpmap)
		num_args = 4;
	else if (func == (sdp_attr_func_ptr)no_specific_ptime)
		num_args = 1;
	else if (func == (sdp_attr_func_ptr)smpte2110_rtpmap)
		num_args = 4;
	return num_args;
}

void set_attr_vinfo(int m_id, int a_id, sdp_attr_func_ptr func, int num_args, ...)
{
	struct attr_validator_info *av = &validator_info.medias[m_id].attributes[a_id];
	av->func = func;

	va_list vl;
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
	} else if (func == (sdp_attr_func_ptr)smpte2110_rtpmap) {
		av->args[0].as.as_ll = va_arg(vl, int);
		av->args[1].as.as_ll = va_arg(vl, int);
		av->args[2].as.as_ll = va_arg(vl, int);
		av->args[3].as.as_ll = va_arg(vl, int);
	}
	va_end(vl);
}

#define SET_ATTR_VINFO(m_id, a_id, func, ...) \
	set_attr_vinfo(m_id, a_id, (sdp_attr_func_ptr)func, num_args((sdp_attr_func_ptr)func), __VA_ARGS__)

static int assert_attr(struct sdp_attr* attr, struct attr_validator_info *av)
{
	int res = 0;
	if (av->func ==  NULL) {
		res = 1;
	} else if (av->func == (sdp_attr_func_ptr)no_specific_fmtp) {
		res = no_specific_fmtp(attr, av->args[0].as.as_ll, av->args[1].as.as_str);
	} else if (av->func == (sdp_attr_func_ptr)no_specific_rtpmap) {
		res = no_specific_rtpmap(attr, av->args[0].as.as_ll, av->args[1].as.as_str, av->args[2].as.as_ll, av->args[3].as.as_str);
	} else if (av->func == (sdp_attr_func_ptr)no_specific_ptime) {
		res = no_specific_ptime(attr, av->args[0].as.as_d);
	} else if (av->func == (sdp_attr_func_ptr)smpte2110_rtpmap) {
		res = smpte2110_rtpmap(attr, av->args[0].as.as_ll, av->args[1].as.as_ll, av->args[2].as.as_ll, av->args[3].as.as_ll);
	} else {
		res = assert_error("Unsupported assertion function %p.\n", av->func);
	}
	return res;
}

static int assert_session_x(struct sdp_session *session)
{
	struct sdp_media *media;
	struct sdp_attr *attr;
	struct media_validator_info *mv;
	struct attr_validator_info *av;
	int m_cnt = 0, a_cnt = 0;
	int res = 1;

	for (media = session->media; media; media = media->next) {
		mv = &validator_info.medias[m_cnt];
		a_cnt = 0;
		for (attr = media->a; attr; attr = attr->next) {
			av = &mv->attributes[a_cnt];
			res &= ASSERT_RES(assert_attr(attr, av));
			++a_cnt;
		}
		if (mv->attr_count != IGNORE_VALUE)
			res &= ASSERT_INT(mv->attr_count, a_cnt);
		++m_cnt;
	}
	if (validator_info.media_count != IGNORE_VALUE)
		res &= ASSERT_INT(validator_info.media_count, m_cnt);
	return res ? 0 : -1;
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
				test_log("%s(): bad source-filter nettype: %d\n",
					__func__,
					source_filter->spec.nettype);
				return -1;
			}

			/* assert source-filter addr type */
			if (source_filter->spec.addrtype !=
					SDP_CI_ADDRTYPE_IPV4) {
				test_log("%s(): bad source-filter addrtype: %d\n",
					__func__,
					source_filter->spec.addrtype);
				return -1;
			}

			/* assert source-filter dst addr */
			if (strncmp(addresses[cnt_m].dst_addr,
					source_filter->spec.dst_addr,
					sizeof(source_filter->spec.dst_addr))) {
				test_log("%s(): bad source-filter dst-addr: %s\n",
					__func__,
					source_filter->spec.dst_addr);
				return -1;
			}

			/* assert source-filter src addr */
			if (strncmp(addresses[cnt_m].src_addr,
					source_filter->spec.src_list.addr,
					sizeof(
					source_filter->spec.src_list.addr))) {
				test_log("%s(): bad source-filter src-addr: %s\n",
					__func__,
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
			test_log("%s() Wrong number of source-filter attributes: "
				"%d\n", __func__, cnt_a);
			return -1;
		}
	}

	if (cnt_m != 2) {
		test_log("%s() Wrong number of media clauses: %d\n", __func__,
			cnt_m);
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

	return test_generic(content, SDP_PARSE_OK, assert_source_filter, smpte2110);
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
		test_log("%s() Wrong number of media clauses: %d\n", __func__,
			cnt_m);
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
			test_log("%s(): last group identification tag points to "
				"dangling location: %p", __func__, tag);
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
		test_log("%s(): found non existing media group identification\n",
			__func__);
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
		"m=video 5000 RTP/AVP 100\n"
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

REG_TEST(test024,
		"sampling parameters")
{
	char *sdp_prefix =
		"v=0\n"
		"o=- 804326665 0 IN IP4 192.168.3.77\n"
		"s=Gefei XIO9101 2110\n"
		"t=0 0\n"
		"m=video 5000 RTP/AVP 100\n"
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
static const char* no_specific_content =
		"v=0\n"
		"s=SDP test\n"
		"t=0 0\n"
		"m=video 50000 RTP/AVP 1234\n"
		"a=rtpmap:100 something/10000\n"
		"a=rtpmap:101 something/20000/params\n"
		"a=fmtp:102 something else\n"
		"a=fmtp:103 something else\n"
		"m=audio 60000 RTP/AVP 5678\n"
		"a=rtpmap:200 something/10000\n"
		"a=rtpmap:201 something/20000/params\n"
		"a=fmtp:202 something else\n"
		"a=fmtp:203 something else\n";

REG_TEST(test025, "PASS - SDP with no specific interpretation/restrictions")
{
	init_session_validator();
	validator_info.media_count = 2;
	validator_info.medias[0].attr_count = 4;
	SET_ATTR_VINFO(0, 0, no_specific_rtpmap, 100, "something", 10000, NULL);
	SET_ATTR_VINFO(0, 1, no_specific_rtpmap, 101, "something", 20000, "params");
	SET_ATTR_VINFO(0, 2, no_specific_fmtp,   102, "something else");
	SET_ATTR_VINFO(0, 3, no_specific_fmtp,   103, "something else");
	validator_info.medias[1].attr_count = 4;
	SET_ATTR_VINFO(1, 0, no_specific_rtpmap, 200, "something", 10000, NULL);
	SET_ATTR_VINFO(1, 1, no_specific_rtpmap, 201, "something", 20000, "params");
	SET_ATTR_VINFO(1, 2, no_specific_fmtp,   202, "something else");
	SET_ATTR_VINFO(1, 3, no_specific_fmtp,   203, "something else");
	return test_generic(no_specific_content, SDP_PARSE_OK, assert_session_x,
			no_specific);
}

REG_TEST(test026, "FAIL - SDP with smpte2110 interpretation/restrictions")
{
	return test_generic_smpte2110_get_error(no_specific_content, SDP_PARSE_ERROR);
}

/******************************************************************************
                                 Payload Type
******************************************************************************/
REG_TEST(test_rtpmap_payload_type_1, "FAIL - smpte2110 rtpmap payload type is not an int")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:xxx L8/10000\n";
	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test_rtpmap_payload_type_2, "FAIL - smpte2110 rtpmap payload type - not found")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 101 102 104\n"
		"a=rtpmap:101 L8/10000\n"
		"a=rtpmap:102 L8/10000\n"
		"a=rtpmap:103 L8/10000\n";
	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test_rtpmap_payload_type_3, "PASS - smpte2110 rtpmap payload type - match eventually")
{
	char* content =
		"v=0\n"
		"s=Testing rtpmap payload type 3\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 101 105 104 102\n"
		"a=rtpmap:101 L8/10000\n"
		"a=rtpmap:102 L8/10000\n"
		"a=rtpmap:103 L8/10000\n"
		"a=rtpmap:104 L8/10000\n"
		"a=rtpmap:105 L8/10000\n"
		"a=rtpmap:106 L8/10000\n";
	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test_rtpmap_payload_type_4, "PASS - smpte2110 rtpmap payload type - 0")
{
	char* content =
		"v=0\n"
		"s=Testing rtpmap payload type 4\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 0\n";
	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

/******************************************************************************
                                 Bit Depth
******************************************************************************/
REG_TEST(test_rtpmap_bit_depth_1, "FAIL - smpte2110 rtpmap bit-depth not specified")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 \n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_rtpmap_bit_depth_2, "FAIL - smpte2110 rtpmap bit-depth not starting with 'L'")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 abc/10000\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_rtpmap_bit_depth_3, "FAIL - smpte2110 rtpmap bit-depth not int")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 Lbc/10000\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

REG_TEST(test_rtpmap_bit_depth_4, "FAIL - smpte2110 rtpmap bit-depth 0")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L0/10000\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, smpte2110);
}

/******************************************************************************
                                 Clock Rate
******************************************************************************/
REG_TEST(test_rtpmap_clock_rate_1, "FAIL - rtpmap clock-rate not specified")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_rtpmap_clock_rate_2, "FAIL - rtpmap clock-rate not int")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/abc\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_rtpmap_clock_rate_3, "FAIL - rtpmap clock-rate 0")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/0\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

/******************************************************************************
                                 Num Channels
******************************************************************************/
REG_TEST(test_rtpmap_num_channels_1, "FAIL - smpte2110 rtpmap num channels not int")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000/abc\n";
	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test_rtpmap_num_channels_2, "FAIL - smpte2110 rtpmap num channels 0")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000/0\n";
	return test_generic_smpte2110_get_error(content, SDP_PARSE_ERROR);
}

REG_TEST(test_rtpmap_num_channels_3, "PASS - smpte2110 rtpmap num channels empty string")
{
	char* content =
		"v=0\n"
		"s=Testing rtpmap num channels 3\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000/\n";

	init_session_validator();
	SET_ATTR_VINFO(0, 0, smpte2110_rtpmap, 100, 24, 10000, 1);
	return test_generic(content, SDP_PARSE_OK, assert_session_x, smpte2110);
}

REG_TEST(test_rtpmap_num_channels_4, "PASS - smpte2110 rtpmap num channels default (NULL)")
{
	char* content =
		"v=0\n"
		"s=Testing rtpmap num channels 4\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=rtpmap:100 L24/10000\n";

	init_session_validator();
	SET_ATTR_VINFO(0, 0, smpte2110_rtpmap, 100, 24, 10000, 1);
	return test_generic_smpte2110_get_error(content, SDP_PARSE_OK);
}

REG_TEST(test_rtpmap_num_channels_5, "PASS - smpte2110 rtpmap num channels specified.")
{
	char* content =
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
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_ptime_2, "FAIL - smpte2110 ptime not int.")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:xxx\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_ptime_3, "FAIL - smpte2110 ptime 0.")
{
	char* content =
		"v=0\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:0\n";
	return test_generic(content, SDP_PARSE_ERROR, NULL, no_specific);
}

REG_TEST(test_ptime_4, "PASS - smpte2110 ptime int.")
{
	char* content =
		"v=0\n"
		"s=Testing ptime 4\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:100\n";
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_ptime, 100.0);
	return test_generic(content, SDP_PARSE_OK, assert_session_x, no_specific);
}

REG_TEST(test_ptime_5, "PASS - smpte2110 ptime double.")
{
	char* content =
		"v=0\n"
		"s=Testing ptime 5\n"
		"t=0 0\n"
		"m=audio 50000 RTP/AVP 100\n"
		"a=ptime:99.5123\n";
	init_session_validator();
	SET_ATTR_VINFO(0, 0, no_specific_ptime, 99.5123);
	return test_generic(content, SDP_PARSE_OK, assert_session_x, no_specific);
}

/******************************************************************************
                                 Test Table
******************************************************************************/
static void init_tests()
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
	ADD_TEST(test026);
	ADD_TEST(test_rtpmap_payload_type_1);
	ADD_TEST(test_rtpmap_payload_type_2);
	ADD_TEST(test_rtpmap_payload_type_3);
	ADD_TEST(test_rtpmap_payload_type_4);
	ADD_TEST(test_rtpmap_bit_depth_1);
	ADD_TEST(test_rtpmap_bit_depth_2);
	ADD_TEST(test_rtpmap_bit_depth_3);
	ADD_TEST(test_rtpmap_bit_depth_4);
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
	/* TODO: (eladw) Test memory deallocation. */
}

/******************************************************************************
                                    Main
******************************************************************************/
int main()
{
	init_tests();
	for (int i = 0; i < num_tests; ++i)
	{
		struct single_test* test = &tests[i];
		print_title("Running test #%u: %s - %s",
			i + 1, test->name, test->description);
		int res = test->func();
		if (res == 0)
		{
			test_log(C_GREEN "Success" C_NORMAL "\n");
		}
		else
		{
			test_log(C_RED "Failure" C_NORMAL "\n");
			return 1;
		}
	}
	return 0;
}
