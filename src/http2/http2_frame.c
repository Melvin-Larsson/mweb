#include "http2_frame.h"

bool http2_frame_try_get_stream_id(uint8_t *buff, size_t len, uint32_t *stream_id){
    if(len < 9){
        return false;
    }

    *stream_id = (buff[5] & 0x7F) << 24 | (buff[6] << 16) | (buff[7] << 8) | buff[8];
    return true;
}

bool http2_frame_try_get_length(uint8_t *buff, size_t buffer_size, size_t *length){
    if(buffer_size < 3){
        return false;
    }
    
    *length = buff[0] << 16 | buff[1] << 8 | buff[2];
    return true;
}


FrameType http2_frame_get_frame_type(uint8_t *buff, size_t len){
    if(len < 4){
        return Invalid;
    }
    return (FrameType)buff[3];
}

ParseStatus http2_frame_parse(ParseBuffer *parse_buffer, GenericFrame *result){
    FrameType type = http2_frame_get_frame_type(&parse_buffer->data[parse_buffer->parsed_size], parse_buffer->total_size - parse_buffer->parsed_size);
    result->type = type;

    switch(type){
        case Data:
            return http2_frame_parse_data_frame(parse_buffer, &result->data_frame);
        case Headers:
            return http2_frame_parse_header_frame(parse_buffer, &result->header_frame);
        case Priority:
            return http2_frame_parse_priority_frame(parse_buffer, &result->priority_frame);
        case RstStream:
            return http2_frame_parse_rst_stream_frame(parse_buffer, &result->rst_frame);
        case Settings:
            return http2_frame_parse_settings_frame(parse_buffer, &result->settings_frame);
        case PushPromise:
            return http2_frame_parse_push_promise_frame(parse_buffer, &result->push_promise_frame);
        case Ping:
            return http2_frame_parse_ping_frame(parse_buffer, &result->ping_frame);
        case GoAway:
            return http2_frame_parse_goaway_frame(parse_buffer, &result->goaway_frame);
        case WindowUpdate:
            return http2_frame_parse_window_update_frame(parse_buffer, &result->window_update_frame);
        case Continuation:
            return http2_frame_parse_continuation_frame(parse_buffer, &result->continuation_frame);
        case Invalid:
            return ParseStatusInvalidFrameType;
    }
}

InternalFrameHeader http2_frame_get_header(const GenericFrame *frame){
    return frame->data_frame.header; //All frames use the same header 
}
