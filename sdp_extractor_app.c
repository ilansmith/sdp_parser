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

static int stream_printf(char *tital, char *flag, ...)
{
	va_list va;
	char format[256];
	char tital_colon[100];
	int ret = 0;

	snprintf(tital_colon, sizeof(tital_colon), "%s:", tital);
	snprintf(format, sizeof(format), "  %s%%-25s%s ",
		C_HIGHLIGHT, C_NORMAL);
	va_start(va, flag);
	switch (*flag) {
	case 's':
		strcat(format, "%s\n");
		printf(format, tital_colon, va_arg(va, char*));
		break;
	case 'i':
		strcat(format, "%i\n");
		printf(format, tital_colon, va_arg(va, int));
		break;
	case 'd':
		strcat(format, "%");
		if (*(flag + 1)) {
			strcat(format, ".");
			strcat(format, (flag + 1));
		}
		strcat(format, "f\n");
		printf(format, tital_colon, va_arg(va, double));
		break;
	default:
		strcat(format, "%s\n");
		printf(format, tital_colon, C_RED "Error" C_NORMAL);
		ret = -1;
		break;
	}
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
	struct code2str types[] = {
		{ TP_2110TPN, "Narrow" },
		{ TP_2110TPNL, "Narrow Linear" },
		{ TP_2110TPW, "Wide" },
		{ -1, "Unknown" }
	};
	char *signal;
	struct code2str scans[] = {
		{ SIGNAL_INTERLACE, "Interlace" },
		{ SIGNAL_PSF, "Progressive segmented Frame (PsF)" },
		{ SIGNAL_PROGRESSIVE, "Progressive" },
		{ -1, "Unknown" }
	};
	struct code2str pms[] = {
		{ PM_2110GPM, "GPM" },
		{ PM_2110BPM, "BPM" },
		{ -1, "Unknown" }
	};

	dump_header();

	parse_input(argc, argv, &sdp_path, &npackets);

	if (dump_sdp(sdp_path))
		abort_printf("Cannot read SDP: %s", sdp_path);

	sdp_extractor = sdp_extractor_init(sdp_path, 0, SDP_STREAM_TYPE_FILE);
	if (!sdp_extractor)
		abort_printf("Unsupported SDP: %s", sdp_path);

	if (npackets && sdp_extractor_set_npackets(sdp_extractor, npackets, 0))
		return -1;

	stream_num = sdp_extractor_get_stream_num(sdp_extractor);
	printf(C_HIGHLIGHT "Extraction:" C_NORMAL "\n");
	stream_printf("Session Name", "s",
		sdp_extractor_get_session_name(sdp_extractor));
	printf("\n");

	for (i = 0; i < stream_num; i++) {
		pm = sdp_extractor_get_packaging_mode(sdp_extractor, i);

		stream_printf("stream", "i", i);
		stream_printf("source ip", "s",
			sdp_extractor_get_src_ip(sdp_extractor, i));
		stream_printf("destination ip", "s",
			sdp_extractor_get_dst_ip(sdp_extractor, i));
		stream_printf("destination port", "i",
			sdp_extractor_get_dst_port(sdp_extractor, i));
		stream_printf("packaging mode", "s", code2str(pms, pm));
		if (sdp_extractor_get_is_rate_integer(sdp_extractor, i)) {
			stream_printf("frames per second", "i",
				(int)sdp_extractor_get_fps(sdp_extractor, i));
		} else {
			stream_printf("frames per second", "d2",
				sdp_extractor_get_fps(sdp_extractor, i));
		}

		if (!npackets && pm == PM_2110BPM)
			npackets = sdp_extractor_get_npackets(sdp_extractor, i);

		if (npackets) {
			stream_printf("npackets", "i",
				sdp_extractor_get_npackets(sdp_extractor, i));
			stream_printf(pm == PM_2110BPM ?
				"packet size" : "approximate packet size", "i",
				sdp_extractor_get_packet_size(sdp_extractor,
					i));
			stream_printf(pm == PM_2110BPM ?
				"rate (Gbps)" : "approximate rate (Gbps)", "d9",
				sdp_extractor_get_rate(sdp_extractor, i) /
				1000000000);
		}

		stream_printf("sender type", "s", code2str(types,
			sdp_extractor_get_type(sdp_extractor, i)));
		signal = code2str(scans, sdp_extractor_get_signal(sdp_extractor,
			i));
		stream_printf("scan", "s", signal ? signal : "Unknown");

		printf("\n");
	}

	sdp_extractor_uninit(sdp_extractor);
	return 0;
}

