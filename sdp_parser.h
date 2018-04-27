#ifndef _SDP_PARSER_
#define _SDP_PARSER_

#define SMPTE_2110_SSN "ST2110-20:2017"

enum sdp_parse_err {
	SDP_PARSE_OK,
	SDP_PARSE_NOT_SUPPORTED,
	SDP_PARSE_ERROR,
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

enum sdp_parse_err sdp_parse_clause_type(char *line,
		char *sdp_description_type);

enum sdp_parse_err sdp_parse_attr_params(char *line, uint32_t *err,
	/* required media type parameters */
	enum smpte_2110_sampling *sampling,
	enum smpte_2110_depth *depth,
	uint16_t *width, uint16_t *height,
	struct smpte_2110_fps *exactframerate,
	enum smpte_2110_colorimetry *colorimetry,
	enum smpte_2110_pm *pm,
	/* media type parameters with default values */
	enum smpte_2110_signal *signal, /* default: SIGNAL_PROGRESSIVE */
	enum smpte_2110_tcs *tcs,       /* default: TCS_SDR */
	enum smpte_2110_range *range,   /* default: RANGE_NARROW */
	uint16_t *maxudp,               /* default: standard UDP limit: 1640 */
	struct smpte_2110_par *par      /* default: 1:1 */
	);
#endif

