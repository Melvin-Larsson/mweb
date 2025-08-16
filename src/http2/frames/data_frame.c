#include "http2/http2_frame.h"
#include "frame_utils.h"
#include "assert.h"
#include <string.h>
#include "http2/http2_logging.h"

InternalDataFrame http2_frame_create_data_frame(uint8_t *data, size_t size, uint32_t stream_id){
    assert(stream_id != 0);

    return (InternalDataFrame){
        .header = (InternalFrameHeader){
            .flags = 0,
            .stream_id = stream_id,
            .type = Data
        },
        .data = (char *)data,
        .size = size
    };
}

ParseStatus http2_frame_parse_data_frame(ParseBuffer *buffer, InternalDataFrame *result){
    InternalFrameHeader header;
    Payload payload_info;

    ParseStatus status = http2_frame_parse_padded_frame(buffer, &header, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(header.type == Data);
    if(header.stream_id == 0){
        return ParseStatusMessageNotAllowdOnStream;
    }
    if((header.flags & ~( END_STREAM | PADDED ))){
        return ParseStatusInvalidFlags;
    }

    *result = (InternalDataFrame){
        .data = payload_info.data,
        .header = header,
        .size = payload_info.size
    };

    return ParseStatusSuccess;
}

size_t http2_frame_serialize_data_frame(char *buffer, size_t len, InternalDataFrame *frame){
    assert((frame->header.flags & ~( END_STREAM | PADDED )) == 0);

    frame->header.type = Data;

    Payload payload_info;
    LOG_DEBUG("Serialize padded frame");
    size_t size = http2_frame_serialize_padded_frame(buffer, len, frame->size, 0, &frame->header, &payload_info);
    memcpy(payload_info.data, frame->data, payload_info.size);

    return size;
}
