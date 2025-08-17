#include "http2_logging.h"
#include "stream/stream.h"
#include <assert.h>


void half_closed_remote_handle_message(Http2Client *client, Stream *stream, const GenericFrame *frame){
    assert(stream->state == HalfClosedRemote);

    switch(frame->type){
        case WindowUpdate:
            stream->window_size += frame->window_update_frame.size_increment;
            return;
        case Priority:
            LOG_DEBUG("Priority is not implementeed for half closed (remote) stream. Ignoring.");
            return;
        default:
            return;
    }
}
