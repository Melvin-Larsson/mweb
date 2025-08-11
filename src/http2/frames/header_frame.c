#include "http2/http2_frame.h"
#include "frame_utils.h"
#include "assert.h"
#include <string.h>

ParseStatus http2_frame_parse_header_frame(ParseBuffer *buffer, InternalHeaderFrame *result){
    InternalFrameHeader header;
    Payload payload_info;
    ParseStatus status = http2_frame_parse_padded_frame(buffer, &header, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(header.type == Headers);

    if(header.stream_id == 0){
        return ParseStatusMessageNotAllowdOnStream;
    }

    if((header.flags & ~(END_STREAM | END_HEADERS | PADDED | PRIORITY))){
        return ParseStatusInvalidFlags;
    }
    
    result->header = header;

    char *header_block_ptr = payload_info.data;
    size_t header_block_size = payload_info.size;
    if(header.flags & PRIORITY){
        ParseStatus status = http2_frame_parse_priority_data(payload_info.data, payload_info.size, &result->priority);
        if(status != ParseStatusSuccess){
            return status;
        }
        header_block_ptr += PRIORITY_DATA_LENGTH;
        header_block_size -= PRIORITY_DATA_LENGTH;
    }

    result->header_block_fragment = header_block_ptr;
    result->header_block_size = header_block_size;

    return ParseStatusSuccess;
}

size_t http2_frame_serialize_header_frame(char *buffer, size_t size, InternalHeaderFrame *frame){
    assert((frame->header.flags & ~(END_STREAM | END_HEADERS | PADDED | PRIORITY)) == 0);

    frame->header.type = Headers;

    size_t payload_size = frame->header_block_size;
    if(frame->header.flags & PRIORITY){
        payload_size += 5;
    }

    Payload payload_info;
    size_t used_size = http2_frame_serialize_padded_frame(buffer, size, payload_size, 0, &frame->header, &payload_info);

    size_t priority_size = 0;
    if(frame->header.flags & PRIORITY){
        priority_size = http2_frame_serialize_priority_data(payload_info.data, payload_info.size, &frame->priority);
        payload_info.size -= priority_size;
        payload_info.data += priority_size;
    }

    memcpy(payload_info.data, frame->header_block_fragment, payload_info.size);

    return used_size;
}
