#ifndef _SMPTE2110_SDP_PARSER_H_
#define _SMPTE2110_SDP_PARSER_H_

#include <stdint.h>
#include "sdp_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* media-level attributes */

enum smpte_2110_media_sub_type {
	SMPTE_2110_SUB_TYPE_UNKNOWN,
	SMPTE_2110_SUB_TYPE_20,
	SMPTE_2110_SUB_TYPE_30,
	SMPTE_2110_SUB_TYPE_40,
};

enum smpte_2110_attr_param_err {
	/* required parameters */
	SMPTE_ERR_SAMPLING = 1<<0,
	SMPTE_ERR_DEPTH = 1<<1,
	SMPTE_ERR_WIDTH = 1<<2,
	SMPTE_ERR_HEIGHT = 1<<3,
	SMPTE_ERR_EXACTFRAMERATE = 1<<4,
	SMPTE_ERR_COLORIMETRY = 1<<5,
	SMPTE_ERR_PM = 1<<6,
	SMPTE_ERR_TP = 1<<7,
	SMPTE_ERR_SSN = 1<<8,
	/* parameters with default values */
	SMPTE_ERR_INERLACE = 1<<9,
	SMPTE_ERR_SEGMENTED = 1<<10,
	SMPTE_ERR_TCS = 1<<11,
	SMPTE_ERR_RANGE = 1<<12,
	SMPTE_ERR_MAXUDP = 1<<13,
	SMPTE_ERR_PAR = 1<<14,
	SMPTE_ERR_TROFF = 1<<15,
	SMPTE_ERR_CMAX = 1<<16,
};

enum smpte_2110_sampling {
	SAMPLING_YCbCr_444,
	SAMPLING_YCbCr_422,
	SAMPLING_YCbCr_420,
	SAMPLING_CLYCbCr_444,
	SAMPLING_CLYCbCr_422,
	SAMPLING_CLYCbCr_420,
	SAMPLING_ICtCp_444,
	SAMPLING_ICtCp_422,
	SAMPLING_ICtCp_420,
	SAMPLING_RGB,
	SAMPLING_XYZ,
	SAMPLING_KEY,
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
	PM_2110BPM,
	PM_2110UNSPECIFIED,
};

enum smpte_2110_tp {
	TP_2110TPN,
	TP_2110TPNL,
	TP_2110TPW,
	TP_UNSPECIFIED,
};

enum smpte_2110_signal {
	SIGNAL_INTERLACE,
	SIGNAL_PSF,
	SIGNAL_PROGRESSIVE,
	SIGNAL_UNSPECIFIED,
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

struct smpte2110_media_attr_fmtp_params {
	enum smpte_2110_sampling sampling;
	enum smpte_2110_depth depth;
	uint16_t width;
	uint16_t height;
	struct smpte_2110_fps exactframerate;
	enum smpte_2110_colorimetry colorimetry;
	enum smpte_2110_pm pm;
	enum smpte_2110_tp tp;
	enum smpte_2110_signal signal;
	enum smpte_2110_tcs tcs;
	enum smpte_2110_range range;
	uint16_t maxudp;
	struct smpte_2110_par par;
	uint64_t troff;
	int cmax;
};

struct smpte2110_media_attr_fmtp {
	struct smpte2110_media_attr_fmtp_params params;
	uint32_t err;
};

struct smpte2110_40_DID_SDID {
	uint8_t code_1;
	uint8_t code_2;
	struct smpte2110_40_DID_SDID *next;
};

struct smpte2110_40_fmtp_params {
	struct smpte2110_40_DID_SDID *DIDs;
	struct smpte2110_40_DID_SDID *last_DID;
	uint32_t VPID_code;
};

/* 2110 specific interpreter */
extern struct sdp_specific *smpte2110;

#ifdef __cplusplus
}
#endif

#endif

