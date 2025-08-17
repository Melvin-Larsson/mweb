#ifndef STREAM_H
#define STREAM_H

#include "buffers.h"
#include "http2/http2.h"
#include "http2_frame.h"
#include <stddef.h>

typedef enum{
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
    Closed
}StreamState;

typedef struct{
    size_t id;
    StreamState state;
    size_t window_size;
}Stream;

void idle_stream_handle_message(Http2Client *client, Stream *stream, const GenericFrame *frame);
void open_stream_handle_message(Http2Client *client, Stream *stream, const GenericFrame *frame);
void half_closed_remote_handle_message(Http2Client *client, Stream *stream, const GenericFrame *frame);
void default_stream_handle_message(Http2Client *client, const GenericFrame *frame);

#endif
