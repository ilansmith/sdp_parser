#include <string.h>

#include "sdp_test_util.h"

#define C_RED    "\033[00;31m"
#define C_GREEN  "\033[00;32m"
#define C_YELLOW "\033[00;33m"
#define C_ITALIC "\033[00;03m"
#define C_NORMAL "\033[00;00;00m"

int test_log(const char *format, ...)
{
	va_list va;
	int ret;

	va_start(va, format);
	ret = fprintf(stderr, "#### ");
	ret += vfprintf(stderr, format, va);
	va_end(va);

	return ret;
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
	size_t len = strlen(content);
	char *tmp;

	tmp = (char*)calloc(len + 1, 1);
	if (!tmp)
		return -1;

	memcpy(tmp, content, len);

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

	ctx = (struct test_ctx*)calloc(1, sizeof(struct test_ctx));
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

void add_test(test_func func, const char *name, const char *description)
{
	int id = num_tests++;
	tests[id].name = name;
	tests[id].description = description;
	tests[id].func = func;
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

int test_generic(const char *content, enum sdp_parse_err expected,
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

/******************************************************************************
                              Common Validators
******************************************************************************/
int assert_error(const char *format, ...)
{
	va_list va;
	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);
	return 0;
}

int assert_str(const char *left_name, const char *left,
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

int assert_int(const char *left_name, long long left,
		const char *right_name, long long right)
{
	if (left != right)
		return assert_error("Assertion failed: %s ('%lld') != %s ('%lld').\n", left_name, left, right_name, right);
	return 1;
}

inline int assert_flt(const char *left_name, double left,
		const char *right_name, double right)
{
	static const double epsilon = 0.00001;
	if (fabs(left - right) > epsilon)
		return assert_error("Assertion failed: %s ('%lf') != %s ('%lf').\n", left_name, left, right_name, right);
	return 1;
}

int assert_res(int res, const char *name, const char* file, int line)
{
	if (!res)
		return assert_error("    In: %s:%u: %s\n", file, line, name);
	return 1;
}

/******************************************************************************
                                Validator Info
******************************************************************************/
struct session_validator_info validator_info;
struct single_test tests[MAX_NUM_TESTS];
int num_tests = 0;

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

int assert_session_x(struct sdp_session *session)
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
