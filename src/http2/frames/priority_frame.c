#include "http2_frame.h"
#include "frame_utils.h"
#include <assert.h>

ParseStatus http2_frame_parse_priority_frame(ParseBuffer *buffer, InternalPriorityFrame *result){
    InternalFrameHeader header;
    Payload paylod_info;
    ParseStatus status = http2_frame_parse_frame_header(buffer, &header, &paylod_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(header.type == Priority);

    if(header.stream_id == 0){
        return ParseStatusMessageNotAllowdOnStream;
    }

    result->header = header;

    return http2_frame_parse_priority_data(paylod_info.data, paylod_info.size, &result->priority);
}

size_t http2_frame_serialize_priority_frame(char *buffer, size_t len, InternalPriorityFrame *frame){
    assert(frame->header.flags == 0);
    assert(frame->header.stream_id != 0);

    frame->header.type = Priority;

    Payload payload_info;
    size_t used_size = http2_frame_serialize_frame_header(buffer, len, 5, &frame->header, &payload_info);

    size_t prio_size = http2_frame_serialize_priority_data(payload_info.data, payload_info.size, &frame->priority);
    assert(prio_size == 5);

    return used_size;
}
