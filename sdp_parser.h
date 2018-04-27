#ifndef _SDP_PARSER_
#define _SDP_PARSER_

#include <stdio.h>

#define SMPTE_2110_SSN "ST2110-20:2017"

enum sdp_parse_err {
	SDP_PARSE_OK,
	SDP_PARSE_NOT_SUPPORTED,
	SDP_PARSE_ERROR,
};

/* connection information description */

enum sdp_ci_nettype {
	SDP_CI_NETTYPE_IN,
	SDP_CI_NETTYPE_NOT_SUPPORTED,
};

enum sdp_ci_addrtype {
	SDP_CI_ADDRTYPE_IPV4,
	SDP_CI_ADDRTYPE_IPV6,
	SDP_CI_ADDRTYPE_NOT_SUPPORTED,
};

 /* c=<nettype> <addrtype> <connection-address> */
struct sdp_connection_information {
	enum sdp_ci_nettype nettype;
	enum sdp_ci_addrtype addrtype;
	char *sdp_ci_addr;
	int sdp_ci_ttl;
	int is_used;
};

/* media description */

enum sdp_media_type {
	SDP_MEDIA_TYPE_VIDEO,
	SDP_MEDIA_TYPE_NOT_SUPPORTED,
};

enum sdp_media_proto {
	SDP_MEDIA_PROTO_RTP_AVP,
	SDP_MEDIA_PROTO_NOT_SUPPORTED,
};

/* m= <media> <port> <proto> <fmt> ... */
struct sdp_media {
	enum sdp_media_type type;
	int port;
	int num_ports;
	enum sdp_media_proto proto;
	int fmt; /* currently supporting a single format per media-level */
};

/* media-level attributes */

enum smpte_2110_attr_param_err {
	/* required parameters */
	SMPTE_ERR_SAMPLING = 1<<0,
	SMPTE_ERR_DEPTH = 1<<1,
	SMPTE_ERR_WIDTH = 1<<2,
	SMPTE_ERR_HEIGHT = 1<<3,
	SMPTE_ERR_EXACTFRAMERATE = 1<<4,
	SMPTE_ERR_COLORIMETRY = 1<<5,
	SMPTE_ERR_PM = 1<<6,
	SMPTE_ERR_SSN = 1<<7,
	/* parameters with default values */
	SMPTE_ERR_INERLACE = 1<<8,
	SMPTE_ERR_SEGMENTED = 1<<9,
	SMPTE_ERR_TCS = 1<<10,
	SMPTE_ERR_RANGE = 1<<11,
	SMPTE_ERR_MAXUDP = 1<<12,
	SMPTE_ERR_PAR = 1<<13,
};

enum smpte_2110_sampling {
	SAMPLING_YCbCr_444,
	SAMPLING_YCbCr_422,
	SAMPLING_YCbCr_420,
};

enum smpte_2110_depth {
	DEPTH_8,
	DEPTH_10,
	DEPTH_12,
	DEPTH_16,
	DEPTH_16F,
};

/* exact frames per second */
struct smpte_2110_fps {
	int is_integer;
	int nominator;
};

enum smpte_2110_colorimetry {
	COLORIMETRY_BT601,
	COLORIMETRY_BT709,
	COLORIMETRY_BT2020,
	COLORIMETRY_BT2100,
	COLORIMETRY_ST2065_1,
	COLORIMETRY_ST2065_3,
	COLORIMETRY_UNSPECIFIED,
};

/* packeging mode */
enum smpte_2110_pm {
	PM_2110GPM,
	PM_2110BPM
};

enum smpte_2110_signal {
	SIGNAL_INTERLACE,
	SIGNAL_PSF,
	SIGNAL_PROGRESSIVE,
};

/* transfer characterstic system */
enum smpte_2110_tcs {
	TCS_SDR,
	TCS_PQ,
	TCS_HLG,
	TCS_LINEAR,
	TCS_BT2100LINPQ,
	TCS_BT2100LINHLG,
	TCS_ST2065_1,
	TCS_ST428_1,
	TCS_DENSITY,
	TCS_UNSPECIFIED
};

enum smpte_2110_range {
	RANGE_NARROW,
	RANGE_FULL,
	RANGE_FULLPROTECT,
};

/* pixel aspect ratio */
struct smpte_2110_par {
	uint32_t width;
	uint32_t height;
};

struct media_attr_fmtp_params {
	enum smpte_2110_sampling sampling;
	enum smpte_2110_depth depth;
	uint16_t width;
	uint16_t height;
	struct smpte_2110_fps exactframerate;
	struct smpte_2110_fps fps;
	enum smpte_2110_colorimetry colorimetry;
	enum smpte_2110_pm pm;
	enum smpte_2110_signal signal;
	enum smpte_2110_tcs tcs;
	enum smpte_2110_range range;
	uint16_t maxudp;
	struct smpte_2110_par par;
};

/* a=fmtp:<val> <params> */
struct media_attr_fmtp {
	uint32_t err;
	struct media_attr_fmtp_params params;
};

struct sdp_media_description {
	struct sdp_media media;

	/* not supported
	   =============

	   i=* (media title)

	 */

	struct sdp_connection_information ci;

	/* not supported
	   =============

         b=* (zero or more bandwidth information lines)
         k=* (encryption key)

	 */

	int media_attr_rtpmap; /* a=rtpmatp:<val> raw/90000 */
	struct media_attr_fmtp fmtp;

	struct sdp_media_description *next;
};

struct sdp_session_description {
	int version; /* v=0 */

	/* not supported
	   =============

	   v=  (protocol version)
	   o=  (originator and session identifier)
	   s=  (session name)
	   i=* (session information)
	   u=* (URI of description)
	   e=* (email address)
	   p=* (phone number)

	 */

	struct sdp_connection_information ci;

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

	struct sdp_media_description *media;
};

enum sdp_parse_err smpte_2110_sdp_session_parse(FILE *sdp,
	struct sdp_session_description *session);
#endif

