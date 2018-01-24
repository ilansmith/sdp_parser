#ifndef _SDP_STREAM_
#define _SDP_STREAM_

#ifdef __cplusplus
extern "C" {
#endif

/* Available stream sources */
enum sdp_stream_type {
	SDP_STREAM_TYPE_FILE, /* Regular file */
	SDP_STREAM_TYPE_CHAR, /* Memory buffer */
	SDP_STREAM_TYPE_USCK, /* UDP socket */
};

typedef void *sdp_stream_t;

/** Open an SDP stream
 * @param type       type of stream to open.
 * @param ctx        input for open function:
 *  - FILE           ctx is a string indicating the path to the file
 *  - CHAR           ctx is a pointer to the memory buffer location
 *  - USCK           TBD
 * 
 * @return an sdp stream context on success, NULL otherwise.
 */
sdp_stream_t sdp_stream_open(enum sdp_stream_type type, void *ctx);

/** Close an SDP stream
 * @param stream     The context of the SDP steram to be closed
 * 
 * @return 0 success, -1 otherwise
 */
int sdp_stream_close(sdp_stream_t stream);

/** Get a single SDP line
 * Reads an entire line from stream, storing the address of the buffer
 * containing the text into *lineptr. The buffer is null-terminated and
 * includes the newline character, if one was found.
 *
 * This functions follows the semantics of POSIX.1-2008 getline(3) but does so
 * for any kind of input stream.
 *
 * @param lineptr    A pointer to the stored location of the line.
 * @param n          The length of the line read (including the newline
 *                   character.
 * @param stream     The context of the SDP steram to use.
 * 
 * @return the number of characters read (including the endofline bug not the
 *         terminating '\0'), -1 otherwise.
 */
ssize_t sdp_stream_getline(char **lineptr, size_t *n, sdp_stream_t stream);

#ifdef __cplusplus
}
#endif

#endif

