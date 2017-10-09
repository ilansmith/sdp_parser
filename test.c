#include <stdio.h>
#include "smpte2110_sdp_parser.h"

enum sdp_parse_err parse_specific_attr(struct sdp_attr *a, char *attr,
	char *value, char *params)
{
	a->sdp_attr_type_specific = 10;
	return SDP_PARSE_OK;
}

int main (int argc, char **argv)
{
	enum sdp_parse_err err;
	struct sdp_session *session;
	char *err2str[] = {
		"SDP_PARSE_OK",
		"SDP_PARSE_NOT_SUPPORTED",
		"SDP_PARSE_ERROR"
	};


	session = sdp_parser_init("./sdp.txt");
	if (!session) {
		printf("failed to initialize sdp session\n");
		return -1;
	}

	err = sdp_session_parse(session, smpte2110_sdp_parse_fmtp_params);
	printf("parsing result: %s\n", err2str[err]);

	sdp_parser_uninit(session);

	return 0;
}

