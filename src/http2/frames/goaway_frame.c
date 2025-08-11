#include "http2/http2_frame.h"
#include "frame_utils.h"
#include "assert.h"

ParseStatus http2_frame_parse_goaway_frame(ParseBuffer *buffer, InternalGoAwayFrame *result){
    InternalFrameHeader frame;
    Payload payload_info;
    ParseStatus status = http2_frame_parse_frame_header(buffer, &frame, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(frame.type == GoAway);

    if(frame.flags != 0){
        return ParseStatusInvalidFlags;
    }

    if(frame.stream_id != 0){
        return ParseStatusMessageNotAllowdOnStream;
    }

    if(payload_info.size < 8){
        return ParseStatusMessageTooSmall;
    }

    *result = (InternalGoAwayFrame){
        .header = frame,
        .last_stream_id = (payload_info.data[0] & 0x7F) << 24 | payload_info.data[1] << 16 | payload_info.data[2] | payload_info.data[3],
        .error_code = payload_info.data[4] << 24 | payload_info.data[5] << 16 | payload_info.data[6] | payload_info.data[7],
        .additional_data = payload_info.data + 8,
        .additional_data_size = payload_info.size - 8
    };
    return ParseStatusSuccess;
}

size_t http2_frame_serialize_goaway_frame(char *buffer, size_t size, InternalGoAwayFrame *frame){
    assert(frame->header.flags == 0);
    assert(frame->header.stream_id == 0);

    frame->header.type = GoAway;

    Payload payload_info;
    size_t used_size = http2_frame_serialize_frame_header(buffer, size, 8 + frame->additional_data_size, &frame->header, &payload_info);

    char last_stream_id[4] = {(frame->last_stream_id & 0xFF000000) >> 24, (frame->last_stream_id & 0xFF0000) >> 16, (frame->last_stream_id & 0xFF00) >> 8, frame->last_stream_id & 0xFF};
    char error_code[4] = {(frame->error_code & 0xFF000000) >> 24, (frame->error_code & 0xFF0000) >> 16, (frame->error_code & 0xFF00) >> 8, frame->error_code & 0xFF};
    _append_bytes(&payload_info.data, &payload_info.size, last_stream_id, 4);
    _append_bytes(&payload_info.data, &payload_info.size, error_code, 4);
    _append_bytes(&payload_info.data, &payload_info.size, frame->additional_data, frame->additional_data_size);

    return used_size;
}
