#include <stdio.h>
#include "smpte2110_sdp_parser.h"

int main (int argc, char **argv)
{
	enum sdp_parse_err err;
	struct sdp_session *session;
	char *err2str[] = {
		"SDP_PARSE_OK",
		"SDP_PARSE_NOT_SUPPORTED",
		"SDP_PARSE_ERROR"
	};


	session = sdp_parser_init(SDP_STREAM_TYPE_FILE, "./sdp.txt");
	if (!session) {
		printf("failed to initialize sdp session\n");
		return -1;
	}

	err = sdp_session_parse(session, smpte2110_sdp_parse_fmtp_params);
	printf("parsing result: %s\n", err2str[err]);

	sdp_parser_uninit(session);

	return 0;
}

