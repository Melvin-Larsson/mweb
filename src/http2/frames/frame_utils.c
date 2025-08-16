#include "http2/http2_frame.h"
#include "frame_utils.h"
#include "assert.h"
#include <string.h>
#include "http2/http2_logging.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

ParseStatus http2_frame_parse_priority_data(char *buff, size_t len, InternalPriorityData *result){
    if(len < PRIORITY_DATA_LENGTH){
        return ParseStatusMessageTooSmall;
    }
    result->exclusive = buff[0] & 0x80 ? true : false;
    result->stream_dependency = ((buff[0] & 0x7F) << 24) | (buff[1] << 16) | (buff[2] << 8) | buff[3];
    result->weight = buff[4];

    return ParseStatusSuccess;
}

size_t http2_frame_serialize_priority_data(char *buff, size_t size, InternalPriorityData *data){
    assert(data->stream_dependency <= 0x7FFFFFFF);

    char stream_dependency[4] = {(data->stream_dependency & 0xFF000000) >> 24, (data->stream_dependency & 0xFF0000) >> 16, (data->stream_dependency & 0xFF00) >> 8, data->stream_dependency & 0xFF};
    if(data->exclusive){
        stream_dependency[0] |= 0x80;
    }

    size_t initial_size = size;
    _append_bytes(&buff, &size, stream_dependency, 4);
    _append_bytes(&buff, &size, (char *)&data->weight, 1);

    return initial_size - size;
}

ParseStatus http2_frame_parse_padded_frame(ParseBuffer *buffer, InternalFrameHeader *result, Payload *payload_info){
    assert(buffer != NULL);
    assert(result != NULL);
    assert(payload_info != NULL);

    ParseStatus status = http2_frame_parse_frame_header(buffer, result, payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }

    size_t size = payload_info->size;
    char *data = payload_info->data;
    if(result->flags & PADDED){
        if(size == 0){
            return ParseStatusMessageTooSmall;
        }
        char padd_length = data[0];
        if(size - 1 <= padd_length){
            return ParseStatusMissingPadding;
        }
        size -= 1 + padd_length;
        data++;
    }

    payload_info->data = data;
    payload_info->size = size;
    return ParseStatusSuccess;
}

size_t http2_frame_serialize_padded_frame(char *buff, size_t size, uint32_t payload_size, uint8_t padding, InternalFrameHeader *frame, Payload *payload_info){
    assert(payload_size + padding + 1<= 0xFFFFFF);

    if(padding == 0){
        frame->flags &= ~PADDED;
        return http2_frame_serialize_frame_header(buff, size, payload_size, frame, payload_info);
    }

    frame->flags |= PADDED;
    size_t used_size = http2_frame_serialize_frame_header(buff, size, payload_size + padding + 1, frame, payload_info);

    _append_bytes(&payload_info->data, &payload_info->size, (char *)&padding, 1);
    if(payload_info->size > payload_size){
        memset(payload_info->data + payload_size, 0, min(payload_info->size - payload_size, padding));
        payload_info->size -= min(payload_info->size - payload_size, padding);
    }

    return used_size;
}

ParseStatus http2_frame_parse_frame_header(ParseBuffer *buffer, InternalFrameHeader *result, Payload *payload_info){
    if(buffer->total_size - buffer->parsed_size < sizeof(ExternalFrameHeader)){
        ERROR("Buffer length of size %zu bytes too small", buffer->total_size - buffer->parsed_size);
        return ParseStatusMessageTooSmall;
    }

    ExternalFrameHeader *externalFrameHeader = (ExternalFrameHeader *)&buffer->data[buffer->parsed_size];
    *result = (InternalFrameHeader){
        .flags = externalFrameHeader->flags,
        .type = externalFrameHeader->type,
        .stream_id = __builtin_bswap32(externalFrameHeader->stream_id),
    };
    *payload_info = (Payload){
        .size = _reverse_byte_order_24(externalFrameHeader->length),
        .data = (uint8_t *)&buffer->data[buffer->parsed_size + 9]
    };

    if(payload_info->size + sizeof(ExternalFrameHeader) > buffer->total_size - buffer->parsed_size){
        ERROR("Message should be of size %zu, but was of size %zu", payload_info->size, buffer->total_size - sizeof(ExternalFrameHeader) - buffer->parsed_size);
        return ParseStatusMessageTooSmall;
    }

    buffer->parsed_size += payload_info->size + 9;

    return ParseStatusSuccess;
}

size_t http2_frame_serialize_frame_header(char *buff, size_t buffer_size, uint32_t payload_size, InternalFrameHeader *header, Payload *payload_info){
    assert(payload_size <= 0xFFFFFF);

    char length_buff[3] = {(payload_size & 0xFF0000) >> 16, (payload_size & 0xFF00) >> 8, payload_size & 0xFF};
    char type = header->type;
    char flags = header->flags;
    char streamd_id[4] = {(header->stream_id & 0xFF000000) >> 24, (header->stream_id & 0xFF0000) >> 16, (header->stream_id & 0xFF00) >> 8, header->stream_id & 0xFF};

    size_t initial_buffer_space = buffer_size;
    _append_bytes(&buff, &buffer_size, length_buff, 3);
    _append_bytes(&buff, &buffer_size, &type, 1);
    _append_bytes(&buff, &buffer_size, &flags, 1);
    _append_bytes(&buff, &buffer_size, streamd_id, 4);

    *payload_info = (Payload){
        .data = buff,
        .size = min(buffer_size, payload_size)
    };

    return initial_buffer_space - buffer_size + payload_info->size;
}

void _append_bytes(char **dst, size_t *dst_len, char *src, size_t src_len){
    size_t copy_len = min(*dst_len, src_len);
    memcpy(*dst, src, copy_len);
    *dst_len -= copy_len;
    *dst += copy_len;
}
