#ifndef HTTP2_COMMON_H
#define HTTP2_COMMON_H

#include "hpack.h"
#include "http2/http2.h"
#include "http2_frame.h"
#include "stream/stream.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

#define PRIORITY_DATA_LENGTH 5
#define DEFAULT_WINDOW_SIZE 65535
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
};

void http2_common_handle_headers(Http2Client *client, Stream *stream, InternalHeaderFrame frame);
bool http2_common_send(Http2Client *client, uint8_t *data, size_t size);
void http2_common_send_goaway(Http2Client *client, ErrorCode error_code);

#endif
