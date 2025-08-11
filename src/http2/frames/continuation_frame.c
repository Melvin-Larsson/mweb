#include "http2/http2_frame.h"
#include "frame_utils.h"
#include "assert.h"

ParseStatus http2_frame_parse_continuation_frame(ParseBuffer *buffer, InternalContinuationFrame *result){
    InternalFrameHeader frame;
    Payload payload_info; 
    ParseStatus status = http2_frame_parse_frame_header(buffer, &frame, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(frame.type == Continuation);

    if(frame.flags & ~(END_HEADERS)){
        return ParseStatusInvalidFlags;
    }

    if(frame.stream_id == 0){
        return ParseStatusMessageNotAllowdOnStream;
    }

    *result = (InternalContinuationFrame){
        .header = frame,
        .header_block_fragment = payload_info.data,
        .header_block_fragment_size = payload_info.size
    };

    return ParseStatusSuccess;
}

size_t http2_frame_serialize_continuation_frame(char *buffer, size_t size, InternalContinuationFrame *frame){
    assert((frame->header.flags & ~(END_HEADERS)) == 0);
    assert(frame->header.stream_id != 0);

    frame->header.type = Continuation;

    Payload payload_info;
    size_t used_size = http2_frame_serialize_frame_header(buffer, size, frame->header_block_fragment_size, &frame->header, &payload_info);
    _append_bytes((char **)&payload_info.data, &payload_info.size, frame->header_block_fragment, frame->header_block_fragment_size);
    return used_size;
}
