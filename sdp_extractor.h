#ifndef _SDP_EXTRACTOR_H_
#define _SDP_EXTRACTOR_H_

#include <stdint.h>
#include "sdp_stream.h"
#include "smpte2022_sdp_parser.h"

typedef void *sdp_extractor_t;

enum sdp_extractor_spec {
	SPEC_SMPTE_ST2022,
	SPEC_SMPTE_ST2110,
	SPEC_UNKNOWN
};

enum sdp_extractor_spec_sub_type {
	SPEC_SUBTYPE_SMPTE_ST2022_6,
	SPEC_SUBTYPE_SMPTE_ST2110_20,
	SPEC_SUBTYPE_SMPTE_ST2110_22,
	SPEC_SUBTYPE_SMPTE_ST2110_30,
	SPEC_SUBTYPE_SMPTE_ST2110_31,
	SPEC_SUBTYPE_SMPTE_ST2110_40,
	SPEC_SUBTYPE_SUBTYPE_UNKNOWN
};

/* Spec agnostic functions */
sdp_extractor_t sdp_extractor_init(void *sdp, enum sdp_stream_type type);
void sdp_extractor_uninit(sdp_extractor_t sdp_extractor);

enum sdp_extractor_spec sdp_extractor_get_spec(sdp_extractor_t sdp_extractor);

char *sdp_extractor_get_session_name(sdp_extractor_t sdp_extractor);
int sdp_extractor_get_stream_num(sdp_extractor_t sdp_extractor);

int sdp_extractor_get_group_num(sdp_extractor_t sdp_extractor);
char *sdp_extractor_get_group_semantic(sdp_extractor_t sdp_extractor,
	int g_idx);
int sdp_extractor_get_group_tag_num(sdp_extractor_t sdp_extractor, int g_idx);
char *sdp_extractor_get_group_tag(sdp_extractor_t sdp_extractor, int g_idx,
	int t_idx);
char *sdp_extractor_stream_to_tag(sdp_extractor_t sdp_extractor, int m_idx);
enum sdp_extractor_spec_sub_type sdp_extractor_stream_sub_type(
	sdp_extractor_t sdp_extractor, int m_idx);

int sdp_extractor_get_group_index_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);

char *sdp_extractor_get_src_ip_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
char *sdp_extractor_get_src_ip_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);
char *sdp_extractor_get_dst_ip_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
char *sdp_extractor_get_dst_ip_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);
uint16_t sdp_extractor_get_dst_port_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
uint16_t sdp_extractor_get_dst_port_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);
int sdp_extractor_get_bandwidth_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx, enum sdp_bandwidth_bwtype bwtype);
int sdp_extractor_get_bandwidth_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx, enum sdp_bandwidth_bwtype bwtype);

/* SMPTE ST2022-06 functions */
int sdp_extractor_get_2022_06_is_rate_integer_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2022_06_is_rate_integer_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

double sdp_extractor_get_2022_06_fps_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
double sdp_extractor_get_2022_06_fps_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

/* SMPTE ST2110-20 functions */
char *sdp_extractor_get_2110_20_encoding_name_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
char *sdp_extractor_get_2110_20_encoding_name_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_20_packaging_mode_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_20_packaging_mode_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

 /* Currently only BPM mode supported */
int sdp_extractor_get_2110_20_packet_size_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_20_packet_size_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

double sdp_extractor_get_2110_20_rate_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
double sdp_extractor_get_2110_20_rate_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_20_is_rate_integer_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_20_is_rate_integer_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_20_npackets_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_20_npackets_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_20_type_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_20_type_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_20_signal_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_20_signal_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_20_width_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_20_width_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_20_height_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_20_height_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

double sdp_extractor_get_2110_20_fps_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
double sdp_extractor_get_2110_20_fps_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_20_colorimetry_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_20_colorimetry_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_20_tcs_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_20_tcs_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_20_range_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_20_range_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_20_par_by_stream(struct smpte_2110_par *par,
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_20_par_by_group(struct smpte_2110_par *par,
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_20_maxudp_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_20_maxudp_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_20_troff_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_20_troff_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_20_cmax_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_20_cmax_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_set_2110_20_npackets(sdp_extractor_t sdp_extractor,
	int npackets);

/* SMPTE ST2110-22 functions */
char *sdp_extractor_get_2110_22_encoding_name_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
char *sdp_extractor_get_2110_22_encoding_name_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_22_width_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_22_width_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_22_height_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_22_height_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_22_is_rate_integer_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_22_is_rate_integer_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

double sdp_extractor_get_2110_22_fps_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
double sdp_extractor_get_2110_22_fps_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_22_type_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_22_type_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

int sdp_extractor_get_2110_22_cmax_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_22_cmax_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

vector_t sdp_extractor_get_2110_22_unrecognized_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
vector_t sdp_extractor_get_2110_22_unrecognized_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_22_unrecognized_num_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_22_unrecognized_num_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

char *sdp_extractor_get_2110_22_val_by_stream(char *key,
	sdp_extractor_t sdp_extractor, int m_idx);
char *sdp_extractor_get_2110_22_val_by_group(char *key,
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

/* SMPTE ST2110-30 functions */
int sdp_extractor_get_2110_30_bit_depth_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
int sdp_extractor_get_2110_30_bit_depth_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

uint32_t sdp_extractor_get_2110_30_sampling_rate_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
uint32_t sdp_extractor_get_2110_30_sampling_rate_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

int sdp_extractor_get_2110_30_num_channels_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_30_num_channels_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

char *sdp_extractor_get_2110_30_channel_order_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
char *sdp_extractor_get_2110_30_channel_order_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);

double sdp_extractor_get_2110_30_ptime_by_stream(sdp_extractor_t sdp_extractor,
	int m_idx);
double sdp_extractor_get_2110_30_ptime_by_group(sdp_extractor_t sdp_extractor,
	int g_idx, int t_idx);

/* SMPTE ST2110-40 functions */
char *sdp_extractor_get_2110_40_encoding_name_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
char *sdp_extractor_get_2110_40_encoding_name_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);
uint8_t **sdp_extractor_get_2110_40_did_sdid_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
uint8_t **sdp_extractor_get_2110_40_did_sdid_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);
int sdp_extractor_get_2110_40_did_sdid_num_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_40_did_sdid_num_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);
uint32_t sdp_extractor_get_2110_40_vpid_code_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
uint32_t sdp_extractor_get_2110_40_vpid_code_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);
int sdp_extractor_get_2110_40_vpid_code_is_set_by_stream(
	sdp_extractor_t sdp_extractor, int m_idx);
int sdp_extractor_get_2110_40_vpid_code_is_set_by_group(
	sdp_extractor_t sdp_extractor, int g_idx, int t_idx);
#endif /* _SDP_EXTRACTOR_H_ */

