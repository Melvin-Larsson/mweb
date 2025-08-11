#include "http2/http2_frame.h"

FrameType http2_frame_get_frame_type(char *buff, size_t len){
    if(len < 4){
        return Invalid;
    }
    return (FrameType)buff[3];
}
