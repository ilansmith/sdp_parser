#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "sdp_parser.h"

#define SDP_DISABLE_LOGGING "SDP_PARSER_DISABLE_LOGGING"

#define SDPOUT(func_suffix, level) \
	enum sdp_parse_err sdp ## func_suffix(char *fmt, ...) \
	{ \
		if (is_logging_disabled) \
			goto exit; \
		\
		va_list va; \
		va_start(va, fmt); \
		sdpout(level, fmt, va); \
		va_end(va); \
		\
	exit: \
		return level; \
	}

static int is_logging_disabled;

static void sdpout(enum sdp_parse_err level, char *fmt, va_list va)
{
	char *prefix;

	switch (level) {
	case SDP_PARSE_WARN:
		prefix = "warning";
		break;
	case SDP_PARSE_ERROR:
		prefix = "error";
		break;
	case SDP_PARSE_DEBUG:
		prefix = "debug";
		break;
	default:
		prefix = "N/A";
		break;
	}

	fprintf(stderr, "SDP parse %s - ", prefix);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	fflush(stderr);
}

void sdp_set_logging(void)
{
	char *val = getenv(SDP_DISABLE_LOGGING);

	is_logging_disabled = val && !strncmp(val, "1", 1) ? 1 : 0;
}

#ifdef CONFIG_DEBUG
SDPOUT(debug, SDP_PARSE_DEBUG)
#endif
SDPOUT(warn, SDP_PARSE_WARN)
SDPOUT(err, SDP_PARSE_ERROR)

