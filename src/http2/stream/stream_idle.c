#include "http2_common.h"
#include "http2_frame.h"
#include "stream/stream.h"
#include "assert.h"

#define LOGG_CONTEXT "Http2"
#include "logging.h"

Task idle_stream_handle_message_async(Http2Client *client, Stream *stream, const GenericFrame *frame, CancellationToken *token){
    assert(stream->state == Idle);

    switch(frame->type){
        case Headers:
            stream->state = Open;
            return open_stream_handle_message_async(client, stream, frame, token);
        case Priority:
            LOG_DEBUG("Prioirity requests are not implemented");
            return completed_task();
        default:
            ERROR("Faulty message type %d in idle state", frame->type);
            http2_common_send_goaway(client, ErrorCodeProtocolError);
            client->status = Stopping;
            return completed_task();
    }
}

