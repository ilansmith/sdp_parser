# sdp_parser
A session description protocol parser ([RFC4566 - SDP](https://www.rfc-editor.org/rfc/rfc4566.txt)).

The motivation for writing this parser was to parse SDP messges for the
SMPTE ST 2110-20 protocol (*Professional Media over Managed IP networks: Uncompressed Active Video*).
As such, it only parses SDP fields which are essential for defining a video
media session, and does so with some constraints.

An example SDP
--------------
<pre>
<b>v=0</b>
o=- 123456 11 IN IP4 192.168.100.2
s=Example of a SMPTE ST2110-20 signal
i=this example is for 720p video at 59.94
t=0 0
a=recvonly
a=group:DUP primary secondary
<b>m=video 50000 RTP/AVP 112</b>
<b>c=IN IP4 239.100.9.10/32</b>
<b>a=source-filter:incl IN IP4 239.100.9.10 192.168.100.2</b>
<b>a=rtpmap:112 raw/90000</b>
<b>a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; exactframerate=60000/1001; depth=10; TCS=SDR; colorimetry=BT709; PM=2110GPM; TP=2110TPN; SSN=ST2110-20:2017;</b>
a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37
a=mediaclk:direct=0
<b>a=mid:primary</b>
<b>m=video 50020 RTP/AVP 112</b>
<b>c=IN IP4 239.101.9.10/32</b>
<b>a=source-filter:incl IN IP4 239.101.9.10 192.168.101.2</b>
<b>a=rtpmap:112 raw/90000</b>
<b>a=fmtp:112 sampling=YCbCr-4:2:2; width=1280; height=720; exactframerate=60000/1001; depth=10; TCS=SDR; colorimetry=BT709; PM=2110GPM; TP=2110TPN; SSN=ST2110-20:2017;</b>
a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37
a=mediaclk:direct=0
<b>a=mid:secondary</b>
</pre>

This SDP defines two streams with the same parameters received at 239.100.9.10:50000 and at 239.101.9.10:50020 (this is clearly an old version of 2110-10 since the required TP= parameter in the a=fmtp attribute is missing).

A few notes
-----------

* Highlighted in <b>bold</b> are the clauses which get parsed by my parser (a.k.a supported fields)
* Supported fields are parsed as defined in RFC4566 (order of appearance/required/optional/format/etc…)
* All non-supported fields can be omitted from the SDP file – the parser will not complain even if they're defined as required by RFC4566
* For any non-supported field of the form ```x=...``` the parser only asserts that ```x``` is a field defined in RFC4566. If it is not, parsing will return an error
* media-level attribute ```a=fmtp:<fmt> <params>```, has its params fully parsed according to 2110-20 and 2110-21, section 8 (according to the versions of the spec I have)
* The parser can easily be extended as required

