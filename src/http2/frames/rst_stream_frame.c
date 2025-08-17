#include "http2_frame.h"
#include "frame_utils.h"
#include <assert.h>

ParseStatus http2_frame_parse_rst_stream_frame(ParseBuffer *buffer, InternalRstStreamFrame *result){
    InternalFrameHeader header;
    Payload payload_info;
    ParseStatus status = http2_frame_parse_frame_header(buffer, &header, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(header.type == RstStream);

    if(header.stream_id != 0){
        return ParseStatusMessageNotAllowdOnStream;
    }

    if(payload_info.size != 4){
        return ParseStatusNotFullMessage;
    }

    result->header = header;
    result->error_code = payload_info.data[0] << 24 | payload_info.data[1] << 16 | payload_info.data[2] << 8 | payload_info.data[3];

    return ParseStatusSuccess;
}


size_t http2_frame_serialize_rst_stream_frame(char *buffer, size_t size, InternalRstStreamFrame *frame){
    assert(frame->header.flags == 0);
    assert(frame->header.stream_id == 0);

    frame->header.type = RstStream;

    Payload payload_info;
    size_t used_size = http2_frame_serialize_frame_header(buffer, size, 4, &frame->header, &payload_info);

    char error_code[4] = {(frame->error_code & 0xFF000000) >> 24, (frame->error_code & 0xFF0000) >> 16, (frame->error_code & 0xFF00) >> 8, frame->error_code & 0xFF};
    _append_bytes(&payload_info.data, &payload_info.size, error_code, 4);

    return used_size;
}
