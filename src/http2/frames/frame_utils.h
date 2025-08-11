#ifndef FRAME_UTILS_H
#define FRAME_UTILS_H

#include "http2/http2_frame.h"

#define PRIORITY_DATA_LENGTH 5
#define _reverse_byte_order_24(x) (((x & 0xFF) << 16) | (x & 0xFF00) | ((x & 0xFF0000) >> 16))

typedef struct{
    unsigned char *data;
    size_t size;
}Payload;

ParseStatus http2_frame_parse_header_frame(ParseBuffer *buffer, InternalHeaderFrame *result);
size_t http2_frame_serialize_frame_header(char *buff, size_t buffer_size, uint32_t payload_size, InternalFrameHeader *header, Payload *payload_info);

ParseStatus http2_frame_parse_priority_data(char *buff, size_t len, InternalPriorityData *result);
size_t http2_frame_serialize_priority_data(char *buff, size_t size, InternalPriorityData *data);

ParseStatus http2_frame_parse_padded_frame(ParseBuffer *buffer, InternalFrameHeader *, Payload *payload_info);
size_t http2_frame_serialize_padded_frame(char *buff, size_t size, uint32_t payload_size, uint8_t padding, InternalFrameHeader *frame, Payload *payload_info);

ParseStatus http2_frame_parse_frame_header(ParseBuffer *buffer, InternalFrameHeader *header, Payload *payload_info);

void _append_bytes(char **dst, size_t *dst_len, char *src, size_t src_len);

#endif
