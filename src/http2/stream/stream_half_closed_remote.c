#include "http2_common.h"
#include "stream/stream.h"
#include <assert.h>

#define LOG_CONTEXT "Http2"
#include "logging.h"


Task half_closed_remove_handle_message_async(Http2Client *client, Stream *stream, const GenericFrame *frame, CancellationToken *token){
    assert(stream->state == HalfClosedRemote);

    switch(frame->type){
        case WindowUpdate:
            stream->window_size += frame->window_update_frame.size_increment;
            LOG_TRACE("Increased window size of stream %d with %d to %d", stream->id, frame->window_update_frame.size_increment, stream->window_size);
            return http2_common_advance_body(client, stream, token);
        case Priority:
            LOG_DEBUG("Priority is not implementeed for half closed (remote) stream. Ignoring.");
            break;
        default:
            break;
    }

    return completed_task();
}
