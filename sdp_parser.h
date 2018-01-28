#ifndef _SDP_PARSER_
#define _SDP_PARSER_

#include <stdio.h>
#include <stdarg.h>

#include "sdp_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STRNLENS_DEFAULT_MAX 100

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
      SDP_ATTR_GROUP,
      SDP_ATTR_RTPMAP,
      SDP_ATTR_FMTP,
      SDP_ATTR_SOURCE_FILTER,
      SDP_ATTR_MID,
      SDP_ATTR_SPECIFIC,
      SDP_ATTR_NOT_SUPPORTED,
};

struct group_identification_tag {
	char *identification_tag;
	struct group_identification_tag *next;
};

/* a=group:<semantic> *<SP identification-tag> */
struct sdp_attr_value_group {
	char *semantic;
	struct group_identification_tag *tag;
	int num_tags;
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

enum sdp_attr_source_filter_mode {
	SDP_ATTR_SRC_FLT_INCL,
	SDP_ATTR_SRC_FLT_EXCL,
};

struct source_filter_src_addr {
	char addr[256];
	struct source_filter_src_addr *next;
};

struct sdp_attr_source_filter_spec {
	enum sdp_ci_nettype nettype;
	enum sdp_ci_addrtype addrtype;
	char dst_addr[256];
	struct source_filter_src_addr src_list;
	int src_list_len;
};

/* a=source-filter:<filter-mode> <filter-spec> */
struct sdp_attr_value_source_filter {
	enum sdp_attr_source_filter_mode mode;
	struct sdp_attr_source_filter_spec spec;
};

/* a=mid:<identification_tag> */
struct sdp_attr_value_mid {
	char *identification_tag;
};

union sdp_attr_value {
	/* Common */

	/* Session */

	/* Media */
	struct sdp_attr_value_group group;
	struct sdp_attr_value_rtpmap rtpmap;
	struct sdp_attr_value_fmtp fmtp;
	struct sdp_attr_value_source_filter source_filter;
	struct sdp_attr_value_mid mid;

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
	*/

	   struct sdp_attr *a;

	/* not supported
	   =============

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

struct sdp_attr *sdp_session_attr_get(struct sdp_session *session,
		enum sdp_attr_type type);

struct sdp_attr *sdp_attr_get_next(struct sdp_attr *attr);

#ifdef __cplusplus
}
#endif

#endif

