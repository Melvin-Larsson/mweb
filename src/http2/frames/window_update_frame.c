#include "http2/http2_frame.h"
#include "frame_utils.h"
#include <assert.h>

ParseStatus http2_frame_parse_window_update_frame(ParseBuffer *buffer, InternalWindowUpdateFrame *result){
    InternalFrameHeader frame;
    Payload payload_info;
    ParseStatus status = http2_frame_parse_frame_header(buffer, &frame, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(frame.type == WindowUpdate);

    if(frame.flags != 0){
        return ParseStatusInvalidFlags;
    }

    if(payload_info.size != 4){
        return ParseStatusMessageTooSmall;
    }

    *result = (InternalWindowUpdateFrame){
        .header = frame,
        .size_increment = (payload_info.data[0] & 0x7F) << 24 | payload_info.data[1] << 16 | payload_info.data[2] | payload_info.data[3],
    };

    if(result->size_increment == 0){
        return ParseStatusInvalidSizeIncrement;
    }

    return ParseStatusSuccess;
}

size_t http2_serialize_window_update_frame(char *buffer, size_t size, InternalWindowUpdateFrame *frame){
    assert(frame->header.flags == 0);

    frame->header.type = WindowUpdate;
    
    Payload payload_info;
    size_t used_size = http2_frame_serialize_frame_header(buffer, size, 4, &frame->header, &payload_info);

    char size_increment[4] = {(frame->size_increment & 0xFF000000) >> 24, (frame->size_increment & 0xFF0000) >> 16, (frame->size_increment & 0xFF00) >> 8, frame->size_increment & 0xFF};
    _append_bytes(&payload_info.data, &payload_info.size, size_increment, 4);

    return used_size;
}
