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
	char *sdp = 
		"v=0\n"
		"o=- 123456 11 IN IP4 192.168.100.2\n"
		"s=Example of a SMPTE ST2110-20 signal\n"
		"i=this example is for 720p video at 59.94\n"
		"t=0 0\n"
		"a=recvonly\n"
		"a=group:DUP primary secondary\n"
		"m=video 50000 RTP/AVP 112\n"
		"c=IN IP4 239.100.9.10/32\n"
		"a=source-filter:incl IN IP4 239.100.9.10 192.168.100.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:primary\n"
		"m=video 50020 RTP/AVP 112\n"
		"c=IN IP4 239.101.9.10/32\n"
		"a=source-filter:incl IN IP4 239.101.9.10 192.168.101.2\n"
		"a=rtpmap:112 raw/90000\n"
		"a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; "
			"exactframerate=60000/1001; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017; \n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37\n"
		"a=mediaclk:direct=0\n"
		"a=mid:secondary\n";

	session = sdp_parser_init(SDP_STREAM_TYPE_CHAR, sdp);
	if (!session) {
		printf("failed to initialize sdp session\n");
		return -1;
	}

	err = sdp_session_parse(session, smpte2110);
	printf("parsing result: %s\n", err2str[err]);

	sdp_parser_uninit(session);

	return 0;
}

