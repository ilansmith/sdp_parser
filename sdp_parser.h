#ifndef _SDP_PARSER_
#define _SDP_PARSER_

#include <stdio.h>
#include <stdarg.h>

#include "sdp_stream.h"

#ifdef _WIN32
#include "sdp_compat.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define IS_WHITESPACE(_char_) ((_char_) == ' ' || (_char_) == '\t')
#define SDP_SPECIFIC_INIT(_name_) { _name_, NULL, NULL, NULL, NULL }

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
	SDP_MEDIA_TYPE_NOT_SUPPORTED,
};

/* sub type should be determined by the specific interpreter*/
enum sdp_media_sub_type {
	SDP_SUB_TYPE_UNKNOWN = 0
};

enum sdp_media_proto {
	SDP_MEDIA_PROTO_RTP_NONE,
	SDP_MEDIA_PROTO_RTP_AVP,
	SDP_MEDIA_PROTO_RTP_SAVP,
	SDP_MEDIA_PROTO_NOT_SUPPORTED,
};

struct sdp_media_fmt {
	int id;
	int sub_type;
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
      SDP_ATTR_PTIME,
      SDP_ATTR_FMTP,
      SDP_ATTR_SOURCE_FILTER,
      SDP_ATTR_MID,
      SDP_ATTR_FRAMERATE,
      SDP_ATTR_SPECIFIC,
      SDP_ATTR_NOT_SUPPORTED,
};

struct interpretable{
	union {
		long long as_ll;
		double as_d;
		void *as_ptr;
		char *as_str;
	} as;
	void (*dtor)(void *params);
};

struct group_identification_tag {
	char *identification_tag;
	struct sdp_media *media;
	struct group_identification_tag *next;
};

/* a=group:<semantic> *<SP identification-tag> */
struct sdp_attr_value_group {
	char *semantic;
	struct group_identification_tag *tag;
	int num_tags;
};

/* a=rtpmap:<payload type> <encoding name>/<clock rate> [/<encoding parameters> */
struct sdp_attr_value_rtpmap {
	struct sdp_media_fmt *fmt; /* payload-type */
	struct interpretable encoding_name;
	int clock_rate;
	struct interpretable encoding_parameters;
};

/* a=ptime:<packet time> */
struct sdp_attr_value_ptime {
	float packet_time;
};

/* a=fmtp:<val> <params> */
struct sdp_attr_value_fmtp {
	struct sdp_media_fmt *fmt;
	struct interpretable params;
};

/* a=framerate:<val> */
struct sdp_attr_value_framerate {
	double frame_rate;
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
	struct sdp_attr_value_ptime ptime;
	struct sdp_attr_value_fmtp fmtp;
	struct sdp_attr_value_framerate framerate;
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
	struct sdp_attr_value_mid *mid;
	struct sdp_attr_value_group *group;
	struct sdp_media *next;
};

struct sdp_session {
	sdp_stream_t sdp;

	struct sdp_session_v v; /* v= */

	/* not supported
	   =============

	   o=  (originator and session identifier)
	*/

	char *s; /* s= */

	/* not supported
	   =============

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

/* Specific interpreter types */
typedef enum sdp_parse_err (*sdp_field_interpreter)(
		struct sdp_media *media, struct sdp_attr *attr,
		struct interpretable *field, char *input);
typedef enum sdp_parse_err (*sdp_attribute_interpreter)(
		struct sdp_media *media, struct sdp_attr *attr, char *value,
		char *params);
typedef enum sdp_parse_err (*sdp_media_validator)(struct sdp_media *media);

/* Media level interpreter */
struct sdp_specific {
	char *name;
	sdp_field_interpreter fmtp_params;
	sdp_field_interpreter rtpmap_encoding_name;
	sdp_field_interpreter rtpmap_encoding_parameters;
	sdp_media_validator validator;
};

/* Empty/default interpreters: */
struct sdp_session_interpreter *no_specific_session_interpreter(void);
struct sdp_media_interpreter *no_specific_media_interpreter(
		struct sdp_media_m *media_m);
extern struct sdp_specific *no_specific;

/* Common API */
struct sdp_session *sdp_parser_init(enum sdp_stream_type type, void *ctx);
void sdp_parser_uninit(struct sdp_session *session);

enum sdp_parse_err sdp_session_parse(struct sdp_session *session,
		struct sdp_specific *specific);

void sdpwarn(char *fmt, ...);
void sdperr(char *fmt, ...);
enum sdp_parse_err sdprerr(char *fmt, ...);

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

