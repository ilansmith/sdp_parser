#ifndef _SDP_LOG_
#define _SDP_LOG_

#include "sdp_parser.h"

#define NOT_USED(x) (void)(x)

/* SDP logging is enabled by default.
 * To disable it, set the following environment variable:
 *
 *     SDP_PARSER_DISABLE_LOGGING=1
 */

void sdp_set_logging(void);

#ifdef CONFIG_DEBUG
enum sdp_parse_err sdpdebug(char *fmt, ...);
#else
static inline enum sdp_parse_err sdpdebug(char *fmt, ...)
{
	NOT_USED(fmt);

	return SDP_PARSE_OK;
}
#endif
enum sdp_parse_err sdpwarn(char *fmt, ...);
enum sdp_parse_err sdperr(char *fmt, ...);

#endif

