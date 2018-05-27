#ifndef _SDP_EXTRACTOR_H_
#define _SDP_EXTRACTOR_H_

#include <stdint.h>
#include "sdp_stream.h"
#include "smpte2022_sdp_parser.h"

typedef void *sdp_extractor_t;

char *sdp_extractor_get_session_name(sdp_extractor_t sdp_extractor);
int sdp_extractor_get_stream_num(sdp_extractor_t sdp_extractor);
int sdp_extractor_get_packaging_mode(sdp_extractor_t sdp_extractor, int dup);
char *sdp_extractor_get_src_ip(sdp_extractor_t sdp_extractor, int dup);
char *sdp_extractor_get_dst_ip(sdp_extractor_t sdp_extractor, int dup);
uint16_t sdp_extractor_get_dst_port(sdp_extractor_t sdp_extractor, int dup);

 /* Currently only BPM mode supported */
int sdp_extractor_get_packet_size(sdp_extractor_t sdp_extractor, int dup);
double sdp_extractor_get_rate(sdp_extractor_t sdp_extractor, int dup);
int sdp_extractor_get_is_rate_integer(sdp_extractor_t sdp_extractor, int dup);
int sdp_extractor_get_npackets(sdp_extractor_t sdp_extractor, int dup);
double sdp_extractor_get_fps(sdp_extractor_t sdp_extractor, int dup);

int sdp_extractor_get_type(sdp_extractor_t sdp_extractor, int dup);
int sdp_extractor_get_signal(sdp_extractor_t sdp_extractor, int dup);

int sdp_extractor_set_npackets(sdp_extractor_t sdp_extractor, int npackets);

void sdp_extractor_uninit(sdp_extractor_t sdp_extractor);
sdp_extractor_t sdp_extractor_init(void *sdp, enum sdp_stream_type type);

#endif /* _SDP_EXTRACTOR_H_ */

