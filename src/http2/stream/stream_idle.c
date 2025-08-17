#include "http2_common.h"
#include "http2_frame.h"
#include "http2_logging.h"
#include "stream/stream.h"
#include "assert.h"

void idle_stream_handle_message(Http2Client *client, Stream *stream, const GenericFrame *frame){
    assert(stream->state == Idle);

    switch(frame->type){
        case Headers:
            stream->state = Open;
            open_stream_handle_message(client, stream, frame);
            return;
        case Priority:
            LOG_DEBUG("Prioirity requests are not implemented");
            return;
        default:
            ERROR("Faulty message type %d in idle state", frame->type);
            http2_common_send_goaway(client, ErrorCodeProtocolError);
            client->status = Stopping;
            return;
    }
}

