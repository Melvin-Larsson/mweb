#include "http2_logging.h"
#include "stream/stream.h"
#include <assert.h>


Task half_closed_remove_handle_message_async(Http2Client *client, Stream *stream, const GenericFrame *frame, CancellationToken *token){
    assert(stream->state == HalfClosedRemote);

    switch(frame->type){
        case WindowUpdate:
            stream->window_size += frame->window_update_frame.size_increment;
            break;
        case Priority:
            LOG_DEBUG("Priority is not implementeed for half closed (remote) stream. Ignoring.");
            break;
        default:
            break;
    }

    return completed_task();
}
