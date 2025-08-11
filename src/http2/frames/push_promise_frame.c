#include "http2/http2_frame.h"
#include "frame_utils.h" 
#include "assert.h"

ParseStatus http2_frame_parse_push_promise_frame(ParseBuffer *buffer, InternalPushPromiseFrame *result){
    InternalFrameHeader header;
    Payload payload_info;
    ParseStatus status = http2_frame_parse_padded_frame(buffer, &header, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(header.type == PushPromise);

    if(header.stream_id == 0){
        return ParseStatusMessageNotAllowdOnStream;
    }

    if((header.flags & ~(END_HEADERS | PADDED)) != 0){
        return ParseStatusInvalidFlags;
    }

    if(payload_info.size <= 4){
        return ParseStatusMessageTooSmall;
    }

    result->header = header;
    result->promised_stream_id = ((payload_info.data[0] & 0x7F) << 24) | (payload_info.data[1] << 16) | (payload_info.data[2] << 8) | payload_info.data[3];

    result->header_block_fragment = (char *)&payload_info.data[4];
    result->header_block_fragment_size = payload_info.size - 4;

    return ParseStatusSuccess;
}

size_t http2_frame_serialize_push_promise_frame(char *buffer, size_t size, InternalPushPromiseFrame *frame){
    assert(frame->header.stream_id != 0);
    assert((frame->header.flags & ~(END_HEADERS | PADDED)) == 0);
    assert(frame->promised_stream_id <= 0x7FFFFFFF);

    frame->header.type = PushPromise;

    Payload payload_info;
    size_t used_size = http2_frame_serialize_padded_frame(buffer, size, 4 + frame->header_block_fragment_size, 0, &frame->header, &payload_info);

    char promised_stream_id[4] = {(frame->promised_stream_id & 0xFF000000) >> 24, (frame->promised_stream_id & 0xFF0000) >> 16, (frame->promised_stream_id & 0xFF00) >> 8, frame->promised_stream_id & 0xFF};
    _append_bytes((char **)&payload_info.data, &payload_info.size, promised_stream_id, 4);
    _append_bytes((char **)&payload_info.data, &payload_info.size, frame->header_block_fragment, frame->header_block_fragment_size);

    return used_size;
}
