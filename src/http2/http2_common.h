#ifndef HTTP2_COMMON_H
#define HTTP2_COMMON_H

#include "hpack.h"
#include "http2/http2.h"
#include "http2_frame.h"
#include "stream/stream.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

#define PRIORITY_DATA_LENGTH 5
#define DEFAULT_WINDOW_SIZE 65535
#define DEFAULT_MAX_FRAME_SIZE 16384
#define MAX_STREAMS_PER_CLIENT 32

typedef enum{
    ConnectionPreface,
    Running,
    Stopping
}ClientStatus;

typedef enum{
    Ok,
    InvaidConnectionPreface,
}Http2InternalStatus;

struct Http2Client{
    ClientStatus status;
    uint32_t highest_client_stream_id;
    uint32_t highest_processed_stream_id;
    Stream streams[MAX_STREAMS_PER_CLIENT];
    HpackEncoder *encoder;
    HpackDecoder *decoder;
    size_t window_size;
    Http2SendCb send_cb;

    size_t initial_window_size;
    size_t max_frame_size;
};

Task http2_common_handle_headers_async(Http2Client *client, Stream *stream, InternalHeaderFrame frame, CancellationToken *token);
bool http2_common_send(Http2Client *client, uint8_t *data, size_t size);
void http2_common_send_goaway(Http2Client *client, ErrorCode error_code);
Task http2_common_advance_body(Http2Client *client, Stream *stream, CancellationToken *token);

#endif
