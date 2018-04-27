#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sdp_stream.h"

struct sdp_stream {
	void *ctx;
	enum sdp_stream_type type;
};

struct buf_stream {
	char *buf;
	size_t offset;
};

/* File stream */
static int sdp_stream_open_file(struct sdp_stream *stream, char *path)
{
	FILE *f;

	if (!(f = fopen(path, "r")))
		return -1;

	stream->ctx = f;
	stream->type = SDP_STREAM_TYPE_FILE;
	return 0;
}

static int sdp_stream_close_file(FILE *f)
{
	return fclose(f);
}

static ssize_t sdp_stream_getline_file(char **lineptr, size_t *n, FILE *f)
{
	return getline(lineptr, n, f);
}

/* Character stream */
static int sdp_stream_open_char(struct sdp_stream *stream, char *buf)
{
	struct buf_stream *bs;

	if (!(bs = (struct buf_stream*)calloc(1, sizeof(struct buf_stream))))
		return -1;

	bs->buf = buf;
	bs->offset = 0;

	stream->ctx = bs;
	stream->type = SDP_STREAM_TYPE_CHAR;
	return 0;
}

static int sdp_stream_close_char(struct buf_stream *bs)
{
	free(bs);
	return 0;
}

static ssize_t sdp_stream_getline_char(char **lineptr, size_t *n,
		struct buf_stream *bs)
{
	char *buf = bs->buf + bs->offset;
	char *eol = strchr(buf, '\n');
	size_t size = eol - buf + 1;

	if (!n)
		return -1;

	if (!*lineptr || *n < size) {
		char *ptr = (char*)realloc(*lineptr, size + 1);

		if (!ptr)
			return -1;

		*n = size + 1;
		*lineptr = ptr;
	}

	memcpy(*lineptr, buf, size);
	(*lineptr)[size] = 0;
	bs->offset += size;
	return size;
}

/* Network stream */

/* Generic stream */
sdp_stream_t sdp_stream_open(enum sdp_stream_type type, void *ctx)
{
	struct sdp_stream *sdp;
	int ret;

	sdp = (struct sdp_stream*)calloc(1, sizeof(struct sdp_stream));
	if (!sdp)
		return NULL;

	switch (type) {
	case SDP_STREAM_TYPE_FILE:
		ret = sdp_stream_open_file(sdp, (char*)ctx);
		break;
	case SDP_STREAM_TYPE_CHAR:
		ret = sdp_stream_open_char(sdp, (char*)ctx);
		break;
	case SDP_STREAM_TYPE_USCK:
	default:
		ret = -1;
		break;
	}

	if (ret) {
		free(sdp);
		return NULL;
	}

	return (sdp_stream_t)sdp;
}

int sdp_stream_close(sdp_stream_t stream)
{
	struct sdp_stream *sdp = (struct sdp_stream*)stream;
	int ret;

	switch (sdp->type) {
	case SDP_STREAM_TYPE_FILE:
		ret = sdp_stream_close_file((FILE*)sdp->ctx);
		break;
	case SDP_STREAM_TYPE_CHAR:
		ret = sdp_stream_close_char((struct buf_stream*)sdp->ctx);
		break;
	case SDP_STREAM_TYPE_USCK:
	default:
		ret = -1;
		break;
	}

	if (!ret)
		free(sdp);

	return ret;
}

ssize_t sdp_stream_getline(char **lineptr, size_t *n, sdp_stream_t stream)
{
	struct sdp_stream *sdp = (struct sdp_stream*)stream;
	ssize_t ret;

	switch (sdp->type) {
	case SDP_STREAM_TYPE_FILE:
		ret = sdp_stream_getline_file(lineptr, n, (FILE*)sdp->ctx);
		break;
	case SDP_STREAM_TYPE_CHAR:
		ret = sdp_stream_getline_char(lineptr, n,
			(struct buf_stream*)sdp->ctx);
		break;
	case SDP_STREAM_TYPE_USCK:
	default:
		ret = -1;
		break;
	}

	return ret;
}

