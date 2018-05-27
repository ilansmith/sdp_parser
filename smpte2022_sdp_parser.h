#ifndef _SMPTE2022_SDP_PARSER_H_
#define _SMPTE2022_SDP_PARSER_H_

#include "sdp_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* media-level attributes */

enum smpte_2022_media_sub_type {
	SMPTE_2022_SUB_TYPE_UNKNOWN,
	SMPTE_2022_SUB_TYPE_6,
};

/* 2022 specific interpreter */
extern struct sdp_specific *smpte2022;

#ifdef __cplusplus
}
#endif

#endif

