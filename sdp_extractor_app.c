#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>

#include "util.h"
#include "smpte2110_sdp_parser.h"
#include "sdp_extractor.h"

#define COPYRIGHT "\u00A9"
#define C_ITALIC "\033[00;3m"
#define C_NORMAL "\033[00;00;00m"
#define C_HIGHLIGHT "\033[01m"
#define C_RED "\033[01;31m"
#define C_ERR(_str_) C_RED _str_ C_NORMAL
#define UDP_SIZE_DEFAULT 1460
#define DEF(_pred_) (_pred_ ? " [default]" : "")
#define ALPHA_NUMERIC(_char_ptr_) ('0' <= *(_char_ptr_) && *(_char_ptr_) <= '9')

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static struct {
	struct option args;
	char *description;
	char *description_arg;
	int is_optional;
} input_opts[] = {
	{
		.args = {
			.name = "sdp",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 's',
		},
		.description = "File containing a SMPTE ST2110-20 SDP",
		.description_arg = "sdp",
		.is_optional = 0,
	},
	{
		.args = {
			.name = "npackets",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'n',
		},
		.description = "Number of packets per frame",
		.description_arg = "num",
		.is_optional = 1,
	},
};

static void abort_printf(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, format, va);
	fprintf(stderr, "\nAborting...\n");
	va_end(va);

	exit(-1);
}

static int do_vprintf(char *format, char **flag, va_list va)
{
	int ret = 0;
	int format_len;
	int inc = 1;

	switch (**flag) {
	case 's':
		strcat(format, "%s");
		printf(format, va_arg(va, char*));
		break;
	case 'i':
		strcat(format, "%i");
		printf(format, va_arg(va, int));
		break;
	case 'h':
		strcat(format, "0x%x");
		printf(format, va_arg(va, int));
		break;
	case 'H':
		strcat(format, "0x%X");
		printf(format, va_arg(va, int));
		break;
	case 'd':
		strcat(format, "%");

		if (ALPHA_NUMERIC(*flag + inc)) {
			strcat(format, ".");
			format_len = strlen(format);
		}

		while (ALPHA_NUMERIC(*flag + inc)) {
			format[format_len + inc - 1] = *(*flag + inc);
			format[format_len + inc] = 0;
			inc++;
		}
		strcat(format, "f");
		printf(format, va_arg(va, double));
		break;
	default:
		strcat(format, "%s");
		printf(format, C_ERR("Error"));
		ret = -1;
		break;
	}

	*flag += inc;
	return ret;
}

static int vstream_printf(char *tital, char *flag, va_list va)
{
	char format[256];
	char tital_colon[100];
	int ret = 0;

	snprintf(tital_colon, sizeof(tital_colon), "%s:", tital);
	snprintf(format, sizeof(format), "  %s%-33s%s ",
		C_HIGHLIGHT, tital_colon, C_NORMAL);
	ret = do_vprintf(format, &flag, va);

	while (!ret && *flag) {
		*format = 0;
		ret = do_vprintf(format, &flag, va);
	}

	printf("\n");
	return ret;
}

static int stream_printf(char *tital, char *flag, ...)
{
	int ret;
	va_list va;

	va_start(va, flag);
	ret = vstream_printf(tital, flag, va);
	va_end(va);

	return ret;
}

static int stream_printf_ind(char *tital, char *flag, ...)
{
	int ret;
	char tital_ind[100];
	va_list va;

	snprintf(tital_ind, sizeof(tital_ind), "  %s", tital);

	va_start(va, flag);
	ret = vstream_printf(tital_ind, flag, va);
	va_end(va);

	return ret;
}

static void dump_header(void)
{
	printf("\n");
	printf("%s%s 2018 IAS Technologies%s\n",
		C_HIGHLIGHT, COPYRIGHT, C_NORMAL);
	printf("\n");
}

static int dump_sdp(char *sdp_path)
{
	FILE *sdp;
	char *line = NULL;
	size_t n = 0;

	sdp = fopen(sdp_path, "r");
	if (!sdp)
		return -1;

	printf(C_HIGHLIGHT "sdp:" C_NORMAL "\n");
	while (getline(&line, &n, sdp) != -1)
		printf("  %s", line);

	printf("\n");

	free(line);
	fclose(sdp);
	return 0;
}

static char *app_name_get(char *arg)
{
	char *app_name;
	
	app_name = strrchr(arg, '/');
	if (app_name)
		app_name += 1;
	else
		app_name = arg;

	return app_name;
}

static void usage(char *app_name)
{
	int i;

	printf("            SMPTE ST2110-20 SDP parser\n");
	printf("\n"
		"%sUsage:   %s [OPTIONS]%s\n"
		"\n"
		"Where %sOPTIONS%s are:\n"
		"\n", C_HIGHLIGHT, app_name, C_NORMAL, C_HIGHLIGHT, C_NORMAL);

	for (i = 0; i < ARRAY_SIZE(input_opts); i++) {
		char options[100];
		char *open = "";
		char *close = "";

		if (input_opts[i].description_arg &&
			input_opts[i].args.has_arg == optional_argument) {
				open = "[";
				close = "]";
		}

		snprintf(options, sizeof(options),
			"%s-%c%s" " %s%s%s" " / " "--%s%s%s" "%s%s%s%s" "%s",
			C_HIGHLIGHT, input_opts[i].args.val, C_NORMAL,
			open, input_opts[i].description_arg, close,
			C_HIGHLIGHT, input_opts[i].args.name, C_NORMAL,
			open, input_opts[i].description_arg ? "=" : "",
			input_opts[i].description_arg, close,
			input_opts[i].is_optional ?
			" (" C_ITALIC "optional" C_NORMAL ")" : "");

		printf("%-15s\n%4s%s\n", options, " ",
			input_opts[i].description);
	}
}

static void print_version(void)
{
	printf(C_HIGHLIGHT "Version: " C_NORMAL " %s\n", SDP_EXTRACTOR_VERSION);
}

static void parse_input(int argc, char **argv, char **sdp_path, int *packets)
{
	char *__sdp_path = NULL;
	int __packets = 0;
	char *app_name;
	char *endptr;
	char *optstring;
	struct option *longopts;
	int i, j;
	int opt;

	app_name = app_name_get(argv[0]);
	if (argc == 1) {
		usage(app_name);
		printf("\n");
		print_version();
		exit(0);
	}

	/* generate longopts */
	longopts = calloc(ARRAY_SIZE(input_opts) + 1, sizeof(struct option));
	if (!longopts)
		abort_printf("could not allocate memory");
	for (i = 0; i < ARRAY_SIZE(input_opts); i++) {
		longopts[i].name = input_opts[i].args.name;
		longopts[i].has_arg = input_opts[i].args.has_arg;
		longopts[i].flag = input_opts[i].args.flag;
		longopts[i].val = input_opts[i].args.val;
	}

	/* generate optstring */
	optstring = calloc(3 * ARRAY_SIZE(input_opts) + 1, sizeof(char));
	if (!optstring)
		abort_printf("could not allocate memory");

	for (i = 0, j = 0; i < ARRAY_SIZE(input_opts); i++) {
		optstring[j++] = longopts[i].val;

		if (longopts[i].has_arg == no_argument)
			continue;

		optstring[j++] = ':';
		if (longopts[i].has_arg == required_argument)
			continue;

		/* longopts[i].has_arg == optional_argument */
		optstring[j++] = ':';
	}

	while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) !=
			-1) {
		switch (opt) {
		case 's':
			if (__sdp_path) {
				abort_printf("sdp file previously set to: "
					"%s", __sdp_path);
			}
			if (!optarg) {
				abort_printf("-s/--sdp requires an "
					"input file name");
			}
			__sdp_path = optarg;
			break;
		case 'n':
			if (__packets) {
				abort_printf("packets previously set to: "
					"%d", __packets);
			}
			if (!optarg) {
				abort_printf("-n/--npackets requires a "
					"number of packets argument");
			}
			__packets = strtol(optarg, &endptr, 10);
			if (*endptr || __packets <= 0) {
				abort_printf("-n/--npackets requires a non "
					"negative integer value: %s", optarg);
			}
			break;
		default:
			usage(app_name);
			exit(-1);
			break;
		}
	}

	free(optstring);
	free(longopts);

	/* validate input */
	if (!__sdp_path)
		abort_printf("SDP file not provided");

	/* init parameters and data structures */
	*sdp_path = __sdp_path;
	*packets = __packets;
}

int main(int argc, char **argv)
{
	char *sdp_path;
	int npackets;
	sdp_extractor_t sdp_extractor;
	int stream_num;
	int i;
	int pm;
	int colorimetry;
	int tcs;
	int range;
	struct smpte_2110_par par;
	int maxudp;
	int troff;
	int cmax;
	int groups_num;
	char *channel_order;
	uint32_t did_sdid_num;
	static struct code2str specs_sub_types[] = {
		{ SPEC_SUBTYPE_SMPTE_ST2022_6, "SMPTE 2022-6" },
		{ SPEC_SUBTYPE_SMPTE_ST2110_20, "SMPTE 2110-20" },
		{ SPEC_SUBTYPE_SMPTE_ST2110_30, "SMPTE 2110-30" },
		{ SPEC_SUBTYPE_SMPTE_ST2110_40, "SMPTE 2110-40" },
		{ -1, C_ERR("Unknown") },
	};
	static struct code2str types[] = {
		{ TP_2110TPN, "Narrow" },
		{ TP_2110TPNL, "Narrow Linear" },
		{ TP_2110TPW, "Wide" },
		{ -1, C_ERR("Unknown") }
	};
	char *signal;
	static struct code2str scans[] = {
		{ SIGNAL_INTERLACE, "Interlace" },
		{ SIGNAL_PSF, "Progressive segmented Frame (PsF)" },
		{ SIGNAL_PROGRESSIVE, "Progressive" },
		{ -1, C_ERR("Unknown") }
	};
	static struct code2str pms[] = {
		{ PM_2110GPM, "GPM" },
		{ PM_2110BPM, "BPM" },
		{ -1, C_ERR("Unknown") }
	};
	static struct code2str colorimetries[] = {
		{ COLORIMETRY_BT601, "BT601" },
		{ COLORIMETRY_BT709, "BT709" },
		{ COLORIMETRY_BT2020, "BT2020" },
		{ COLORIMETRY_BT2100, "BT2100" },
		{ COLORIMETRY_ST2065_1, "ST2065_1" },
		{ COLORIMETRY_ST2065_3, "ST2065_3" },
		{ -1, C_ERR("Unknown") },
	};
	static struct code2str xfer_characteristic_system[] = {
		{ TCS_SDR, "SCR" },
		{ TCS_PQ, "PQ" },
		{ TCS_HLG, "HLG" },
		{ TCS_LINEAR, "LINEAR" },
		{ TCS_BT2100LINPQ, "BT2100LINPQ" },
		{ TCS_BT2100LINHLG, "BT2100LINHLG" },
		{ TCS_ST2065_1, "ST2065_1" },
		{ TCS_ST428_1, "ST428_1" },
		{ TCS_DENSITY, "DENSITY" },
		{ -1, C_ERR("Unknown") },
	};
	static struct code2str ranges[] = {
		{ RANGE_NARROW, "NARROW" },
		{ RANGE_FULL, "FULL" },
		{ RANGE_FULLPROTECT, "FULLPROTECT" },
		{ -1, C_ERR("Unknown") },
	};
	static struct code2str bwtypes[] = {
		{ SDP_BWTYPE_CT, "CT" },
		{ SDP_BWTYPE_AS, "AS" },
		{ SDP_BWTYPE_RR, "RR" },
		{ SDP_BWTYPE_RS, "RS" },
		{ SDP_BWTYPE_TIAS, "TIAS" },
		{ SDP_BWTYPE_UNKNOWN, "Unknown" },
		{ -1, C_ERR("Not Supported") },
	};

	dump_header();

	parse_input(argc, argv, &sdp_path, &npackets);

	if (dump_sdp(sdp_path))
		abort_printf("Cannot read SDP: %s", sdp_path);

	sdp_extractor = sdp_extractor_init(sdp_path, SDP_STREAM_TYPE_FILE);
	if (!sdp_extractor)
		abort_printf("Unsupported SDP: %s", sdp_path);

	if (npackets && sdp_extractor_set_2110_20_npackets(sdp_extractor,
			npackets)) {
		return -1;
	}

	stream_num = sdp_extractor_get_stream_num(sdp_extractor);
	printf(C_HIGHLIGHT "Extraction:" C_NORMAL "\n");
	stream_printf("Session Name", "s",
		sdp_extractor_get_session_name(sdp_extractor));
	printf("\n");

	groups_num = sdp_extractor_get_group_num(sdp_extractor);
	for (i = 0; i < groups_num; i++) {
		int tag_num = sdp_extractor_get_group_tag_num(sdp_extractor, i);
		int j;

		stream_printf("group index", "i", i);
		stream_printf_ind("semantic", "s",
			sdp_extractor_get_group_semantic(sdp_extractor, i));
		for (j = 0; j < tag_num; j++) {
			stream_printf_ind("identification tag", "s",
				sdp_extractor_get_group_tag(sdp_extractor, i,
					j));
		}

		printf("\n");
	}
	if (groups_num)
		printf("\n");

	for (i = 0; i < stream_num; i++) {
		char resolution[20];
		int g_idx;
		enum sdp_extractor_spec_sub_type sub_type =
			sdp_extractor_stream_sub_type(sdp_extractor, i);
		enum sdp_bandwidth_bwtype bwtype;

		stream_printf("stream index", "i", i);
		stream_printf_ind("spec sub type", "s",
			code2str(specs_sub_types, sub_type));
		stream_printf_ind("source ip", "s",
			sdp_extractor_get_src_ip_by_stream(sdp_extractor, i));
		stream_printf_ind("destination ip", "s",
			sdp_extractor_get_dst_ip_by_stream(sdp_extractor, i));
		stream_printf_ind("destination port", "i",
			sdp_extractor_get_dst_port_by_stream(sdp_extractor, i));
		for (bwtype = SDP_BWTYPE_CT; bwtype < SDP_BWTYPE_UNKNOWN;
				bwtype++) {
			int bandwidth;

			bandwidth = sdp_extractor_get_bandwidth_by_stream(
					sdp_extractor, i, bwtype);
			if (bandwidth) {
				stream_printf_ind("bandwidth", "ssi",
					code2str(bwtypes, bwtype), ", ",
					bandwidth);
			}
		}

		switch (sub_type) {
		case SPEC_SUBTYPE_SMPTE_ST2022_6:
			stream_printf_ind("frames per second", "i",
				(int)sdp_extractor_get_2022_06_fps_by_stream(
					sdp_extractor, i));
			break;
		case SPEC_SUBTYPE_SMPTE_ST2110_20:
			if (sdp_extractor_get_2110_20_is_rate_integer_by_stream(
					sdp_extractor, i)) {
				stream_printf_ind("frames per second", "i",
					(int)sdp_extractor_get_2110_20_fps_by_stream(
						sdp_extractor, i));
			} else {
				stream_printf_ind("frames per second", "d2",
					sdp_extractor_get_2110_20_fps_by_stream(
						sdp_extractor, i));
			}

			snprintf(resolution, sizeof(resolution), "%ix%i",
				sdp_extractor_get_2110_20_height_by_stream(
					sdp_extractor, i),
				sdp_extractor_get_2110_20_width_by_stream(
					sdp_extractor, i));
			stream_printf_ind("resolution", "s", resolution);

			pm = sdp_extractor_get_2110_20_packaging_mode_by_stream(
				sdp_extractor, i);
			stream_printf_ind("packaging mode", "s",
				code2str(pms, pm));

			if (!npackets && pm == PM_2110BPM)
				npackets =
					sdp_extractor_get_2110_20_npackets_by_stream(
					sdp_extractor, i);

			if ((maxudp =
				sdp_extractor_get_2110_20_maxudp_by_stream(
				sdp_extractor, i))) {
					stream_printf_ind("max udp", "is",
						maxudp, DEF(maxudp ==
							UDP_SIZE_DEFAULT));
			}

			if (npackets) {
				int packet_size =
					sdp_extractor_get_2110_20_packet_size_by_stream(
						sdp_extractor, i);
				int is_valid;
				
				is_valid = packet_size <= maxudp;

				stream_printf_ind("npackets", "is",
					sdp_extractor_get_2110_20_npackets_by_stream(
						sdp_extractor, i),
					is_valid ? "" :
					" (" C_ERR("too few") ")");
				stream_printf_ind(pm == PM_2110BPM ?
					"packet size" :
					"approximate packet size", "is",
					packet_size,
					is_valid ? "" :
					" (" C_ERR("too large") ") ");
				stream_printf_ind(pm == PM_2110BPM ?
					"rate (Gbps)" :
					"approximate rate (Gbps)", "d",
					sdp_extractor_get_2110_20_rate_by_stream(
						sdp_extractor, i) / 1000000000);
			}

			stream_printf_ind("sender type", "s", code2str(types,
				sdp_extractor_get_2110_20_type_by_stream(
					sdp_extractor, i)));
			signal = code2str(scans,
				sdp_extractor_get_2110_20_signal_by_stream(
					sdp_extractor, i));
			stream_printf_ind("scan", "s",
				signal ? signal : C_ERR("Unknown"));

			if ((cmax = sdp_extractor_get_2110_20_cmax_by_stream(
				sdp_extractor, i))) {
					stream_printf_ind("cmax", "i", cmax);
			}

			if ((troff = sdp_extractor_get_2110_20_troff_by_stream(
				sdp_extractor, i))) {
					stream_printf_ind("tr offset", "i",
						troff);
			}

			if ((colorimetry =
				sdp_extractor_get_2110_20_colorimetry_by_stream(
				sdp_extractor, i)) != COLORIMETRY_UNSPECIFIED) {
				stream_printf_ind("colorimetry", "s",
					code2str(colorimetries, colorimetry));
			}

			if ((tcs = sdp_extractor_get_2110_20_tcs_by_stream(
					sdp_extractor, i)) != TCS_UNSPECIFIED) {
				stream_printf_ind("transfer characteristic "
					"system", "s",
					code2str(xfer_characteristic_system,
						tcs));
			}

			range = sdp_extractor_get_2110_20_range_by_stream(
				sdp_extractor, i);
			stream_printf_ind("range", "sss",
				code2str(ranges, range),
				range == RANGE_FULLPROTECT &&
					colorimetry != COLORIMETRY_BT2100 ?
					" (" C_ERR("allowed only with "
						"colorimetry bt2100") ")" : "",
					DEF(range == RANGE_NARROW));

			sdp_extractor_get_2110_20_par_by_stream(&par,
				sdp_extractor, i);
			stream_printf_ind("pixel aspect ratio", "isis",
				par.width, ":", par.height,
				DEF(par.width == 1 && par.height == 1));
			break;
		case SPEC_SUBTYPE_SMPTE_ST2110_30:
			stream_printf_ind("sampling rate", "i",
				sdp_extractor_get_2110_30_sampling_rate_by_stream(
					sdp_extractor, i));

			stream_printf_ind("bit depth", "i",
				sdp_extractor_get_2110_30_bit_depth_by_stream(
					sdp_extractor, i));
			stream_printf_ind("num channels", "i",
				sdp_extractor_get_2110_30_num_channels_by_stream(
					sdp_extractor, i));
			stream_printf_ind("packet time", "d",
				sdp_extractor_get_2110_30_ptime_by_stream(
					sdp_extractor, i));
			channel_order =
				sdp_extractor_get_2110_30_channel_order_by_stream(
					sdp_extractor, i);
				stream_printf_ind("channel order", "s",
					channel_order ? channel_order : "N/A");
			break;
		case SPEC_SUBTYPE_SMPTE_ST2110_40:
			did_sdid_num = sdp_extractor_get_2110_40_did_sdid_num_by_stream(
				sdp_extractor, i);
			if (did_sdid_num) {
				uint8_t **did_sdid;
				uint32_t j;
				
				did_sdid = sdp_extractor_get_2110_40_did_sdid_by_stream(
					sdp_extractor, i);
				for (j = 0; j < did_sdid_num; j++) {
					stream_printf_ind("did sdid", "HsH",
						did_sdid[j][0], ", ",
						did_sdid[j][1]);
				}
			}

			if (sdp_extractor_get_2110_40_vpid_code_is_set_by_stream(
					sdp_extractor, i)) {
				stream_printf_ind("vpid code", "i",
					sdp_extractor_get_2110_40_vpid_code_by_stream(
						sdp_extractor, i));
			}
			break;
		case SPEC_SUBTYPE_SUBTYPE_UNKNOWN:
		default:
			break;
		}

		g_idx = sdp_extractor_get_group_index_by_stream(sdp_extractor,
			i);
		if (0 <= g_idx) {
			stream_printf_ind("group", "s",
				sdp_extractor_get_group_semantic(sdp_extractor,
					g_idx));
			stream_printf_ind("identification tag", "s",
				sdp_extractor_stream_to_tag(sdp_extractor, i));
		}

		printf("\n");
	}

	sdp_extractor_uninit(sdp_extractor);
	return 0;
}

