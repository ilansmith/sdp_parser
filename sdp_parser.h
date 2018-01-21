#ifndef _SDP_PARSER_
#define _SDP_PARSER_

#include <stdio.h>
#include <stdarg.h>

#include "sdp_stream.h"

#define IS_WHITESPACE(_char_) ((_char_) == ' ' || (_char_) == '\t')

enum sdp_parse_err {
	SDP_PARSE_OK,
	SDP_PARSE_NOT_SUPPORTED,
	SDP_PARSE_ERROR,
};

/* sdp version */

struct sdp_session_v {
	int version;
};

/* sdp connection information description */

enum sdp_ci_nettype {
	SDP_CI_NETTYPE_NONE,
	SDP_CI_NETTYPE_IN,
	SDP_CI_NETTYPE_NOT_SUPPORTED,
};

enum sdp_ci_addrtype {
	SDP_CI_ADDRTYPE_NONE,
	SDP_CI_ADDRTYPE_IPV4,
	SDP_CI_ADDRTYPE_IPV6,
	SDP_CI_ADDRTYPE_NOT_SUPPORTED,
};

 /* c=<nettype> <addrtype> <connection-address> */
struct sdp_connection_information {
	enum sdp_ci_nettype nettype;
	enum sdp_ci_addrtype addrtype;
	char sdp_ci_addr[256];
	int sdp_ci_ttl;
	int count;
};

/* media description */

enum sdp_media_type {
	SDP_MEDIA_TYPE_NONE,
	SDP_MEDIA_TYPE_AUDIO,
	SDP_MEDIA_TYPE_VIDEO,
	SDP_MEDIA_TYPE_TEXT,
	SDP_MEDIA_TYPE_APPLICTION,
	SDP_MEDIA_TYPE_MESSAGE,
	SDP_MEDIA_TYPE_NOT_SUPPORTED,
};

enum sdp_media_proto {
	SDP_MEDIA_PROTO_RTP_NONE,
	SDP_MEDIA_PROTO_RTP_AVP,
	SDP_MEDIA_PROTO_RTP_SAVP,
	SDP_MEDIA_PROTO_NOT_SUPPORTED,
};

struct sdp_media_fmt {
	int id;
	struct sdp_media_fmt *next;
};

/* m= <media> <port> <proto> <fmt> ... */
struct sdp_media_m {
	enum sdp_media_type type;
	int port;
	int num_ports;
	enum sdp_media_proto proto;
	struct sdp_media_fmt fmt;
};

/* a=<attribute> / a=<attribute>:<value> */
enum sdp_attr_type {
      SDP_ATTR_NONE,
      SDP_ATTR_RTPMAP,
      SDP_ATTR_FMTP,
      SDP_ATTR_SPECIFIC,
      SDP_ATTR_NOT_SUPPORTED,
};

/* a=rtpmap:<val> <subytype>/<clock> */
struct sdp_attr_value_rtpmap {
	int fmt;
	char media_subtype[64];
	int clock_rate;
};

/* a=fmtp:<val> <params> */
struct sdp_attr_value_fmtp {
	int fmt;
	void *params;
	void (*param_dtor)(void *params);
};

union sdp_attr_value {
	/* Common */

	/* Session */

	/* Media */
	struct sdp_attr_value_rtpmap rtpmap;
	struct sdp_attr_value_fmtp fmtp;

	/* Specific */
	void *specific;
};

struct sdp_attr {
	enum sdp_attr_type type;
	union sdp_attr_value value;
	struct sdp_attr *next;
};

struct sdp_media {
	struct sdp_media_m m;

	/* not supported
	   =============

	   i=* (media title)

	 */

	struct sdp_connection_information c; /* c=* */

	/* not supported
	   =============

         b=* (zero or more bandwidth information lines)
         k=* (encryption key)

	 */

	struct sdp_attr *a; /* a=* */
	struct sdp_media *next;
};

struct sdp_session {
	sdp_stream_t sdp;

	struct sdp_session_v v; /* v= */

	/* not supported
	   =============

	   o=  (originator and session identifier)
	   s=  (session name)
	   i=* (session information)
	   u=* (URI of description)
	   e=* (email address)
	   p=* (phone number)

	 */

	struct sdp_connection_information c; /* c=* */

	/* not supported
	   =============

	   b=* (zero or more bandwidth information lines)
	   One or more time descriptions ("t=" and "r=" lines; see below)
	   z=* (time zone adjustments)
	   k=* (encryption key)
	   a=* (zero or more session attribute lines)

	   Time description
	   ----------------
	   t=  (time the session is active)
	   r=* (zero or more repeat times)

	 */

	struct sdp_media *media; /* media-level descriptor(s) */
};

typedef enum sdp_parse_err (*parse_attr_specific_t)(struct sdp_attr *a,
	char *attr, char *value, char *params);

struct sdp_session *sdp_parser_init(enum sdp_stream_type type, void *ctx);
void sdp_parser_uninit(struct sdp_session *session);

enum sdp_parse_err sdp_session_parse(struct sdp_session *session,
		parse_attr_specific_t parse_attr_specific);

void sdpwarn(char *fmt, ...);
void sdperr(char *fmt, ...);

/* Accessors */
struct sdp_media *sdp_media_get(struct sdp_session *session,
		enum sdp_media_type type);

struct sdp_media *sdp_media_get_next(struct sdp_media *media);

struct sdp_attr *sdp_media_attr_get(struct sdp_media *media,
		enum sdp_attr_type type);

struct sdp_attr *sdp_media_attr_get_next(struct sdp_attr *attr);
#endif

