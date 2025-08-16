#include "http2/http2_frame.h"

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


FrameType http2_frame_get_frame_type(char *buff, size_t len){
    if(len < 4){
        return Invalid;
    }
    return (FrameType)buff[3];
}
