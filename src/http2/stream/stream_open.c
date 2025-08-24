#include "http2_common.h"
#include "http2_frame.h"
#include "http2_logging.h"
#include "stream/stream.h"
#include <assert.h>

static void _open_stream_handle_headers(Http2Client *client, Stream *stream, InternalHeaderFrame frame);
static void _open_stream_handle_data(Http2Client *client, Stream *stream, InternalDataFrame frame);
static void _open_stream_handle_window_update(Http2Client *client, Stream *stream, InternalWindowUpdateFrame frame);
static void _open_stream_handle_continuation(Http2Client *client, Stream *stream, InternalContinuationFrame frame);

Task open_stream_handle_message_async(Http2Client *client, Stream *stream, const GenericFrame *frame, CancellationToken *token){
    InternalFrameHeader header = http2_frame_get_header(frame);

    Task task = completed_task();
    switch(frame->type){
        case Data:
            _open_stream_handle_data(client, stream, frame->data_frame);
            break;
        case Headers:
            task = http2_common_handle_headers_async(client, stream, frame->header_frame, token);
            break;
        case WindowUpdate:
            stream->window_size += frame->window_update_frame.size_increment;
            break;
        case Continuation:
            _open_stream_handle_continuation(client, stream, frame->continuation_frame);
            break;
        case Priority:
            LOG_DEBUG("Prioirity requests are not implemented");
            break;
        default:
            ERROR("Invalid message type %d received on open stream", frame->type);
            http2_common_send_goaway(client, ErrorCodeProtocolError);
    }

    if(header.flags & END_STREAM && stream->state == Open){
        stream->state = HalfClosedRemote;
    }

    return task;
}

static void _open_stream_handle_data(Http2Client *client, Stream *stream, InternalDataFrame frame){
    LOG_DEBUG("Handle data not implemented");
}

static void _open_stream_handle_continuation(Http2Client *client, Stream *stream, InternalContinuationFrame frame){
    LOG_DEBUG("Open stream continuation not implemented");
}
