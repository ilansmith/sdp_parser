#ifndef _SDP_LOG_
#define _SDP_LOG_

#include "sdp_parser.h"

#ifdef CONFIG_DEBUG
enum sdp_parse_err sdpdebug(char *fmt, ...);
#else
static inline enum sdp_parse_err sdpdebug(char *fmt, ...)
{
	return SDP_PARSE_OK;
}
#endif
enum sdp_parse_err sdpwarn(char *fmt, ...);
enum sdp_parse_err sdperr(char *fmt, ...);

#endif

