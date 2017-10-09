#include <stdio.h>
#include "sdp_parser.h"

static int parse_specific_attr(struct sdp_attr *a, char *attr, char *value,
		char *params)
{
	a->sdp_attr_type_specific = 10;
	return 0;
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

	err = sdp_session_parse(session, parse_specific_attr);
	printf("parsing result: %s\n", err2str[err]);

	sdp_parser_uninit(session);

	return 0;
}

