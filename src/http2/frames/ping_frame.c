#include "http2/http2_frame.h"
#include "frame_utils.h"
#include <assert.h>
#include <string.h>

ParseStatus http2_frame_parse_ping_frame(ParseBuffer *buffer, InternalPingFrame *result){
    InternalFrameHeader frame;
    Payload payload_info;
    ParseStatus status = http2_frame_parse_frame_header(buffer, &frame, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(frame.type == Ping);

    if(frame.flags & ~ACK){
        return ParseStatusInvalidFlags;
    }

    if(frame.stream_id != 0){
        return ParseStatusMessageNotAllowdOnStream;
    }

    result->header = frame;

    if(payload_info.size != 8){
        return ParseSatusInvalidMessageSize;
    }

    memcpy(&result->data, payload_info.data, 8);

    return ParseStatusSuccess;
}

size_t http2_frame_serialize_ping_frame(char *buffer, size_t size, InternalPingFrame *frame){
    assert((frame->header.flags & ~ACK) == 0);
    assert(frame->header.stream_id == 0);

    frame->header.type = Ping;

    Payload payload_info;
    size_t used_size = http2_frame_serialize_frame_header(buffer, size, 8, &frame->header, &payload_info);
    _append_bytes(&payload_info.data, &payload_info.size, (char *)&frame->data, 8);

    return used_size;
}
