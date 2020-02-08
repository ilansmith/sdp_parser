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
		"o=- 123456 2 IN IP4 192.168.1.2\n"
		"s=SMPTE ST2110-20/30/40 streams\n"
		"i=Includes 1080i@29.97 Hz video, one stereo pair of PCM "
			"audio, and ANC\n"
		"t=0 0\n"
		"a=recvonly\n"
		"a=group:DUP primary secondary\n"
		"a=group:DUP third fourth\n"
		"m=video 50020 RTP/AVP 96\n"
		"c=IN IP4 224.1.1.1/64\n"
		"a=source-filter: incl IN IP4 224.1.1.1 192.168.1.2\n"
		"a=rtpmap:96 raw/90000\n"
		"a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; "
			"exactframerate=25; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017\n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:127\n"
		"a=mediaclk:direct=0\n"
		"a=mid:primary\n"
		"m=audio 50030 RTP/AVP 97\n"
		"c=IN IP4 224.1.1.1/64\n"
		"a=source-filter: incl IN IP4 224.1.1.1 192.168.1.2\n"
		"a=rtpmap:97 L24/48000/2\n"
		"a=fmtp:97 channel-order=SMPTE2110.(ST)\n"
		"a=ptime:1\n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:127\n"
		"a=mediaclk:direct=0\n"
		"a=mid:third\n"
		"m=video 50021 RTP/AVP 98\n"
		"c=IN IP4 224.1.1.1/64\n"
		"a=source-filter: incl IN IP4 224.1.1.1 192.168.1.2\n"
		"a=rtpmap:98 raw/90000\n"
		"a=fmtp:98 sampling=YCbCr-4:2:2; width=1920; height=1080; "
			"exactframerate=25; depth=10; TCS=SDR; "
			"colorimetry=BT709; PM=2110GPM; TP=2110TPN; "
			"SSN=ST2110-20:2017\n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:127\n"
		"a=mediaclk:direct=0\n"
		"a=mid:secondary\n"
		"m=video 50040 RTP/AVP 100\n"
		"c=IN IP4 224.1.1.1/64\n"
		"a=source-filter: incl IN IP4 224.1.1.1 192.168.1.2\n"
		"a=rtpmap:100 smpte291/90000\n"
		"a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:127\n"
		"a=mediaclk:direct=0\n"
		"a=mid:fourth\n";

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

