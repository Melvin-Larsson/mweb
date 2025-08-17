#ifndef HPACK_H
#define HPACK_H

#include <stddef.h>
#include "buffers.h"
#include "hpack_primitives.h"
#include "http_message.h"

typedef struct HpackEncoder HpackEncoder;
typedef struct HpackDecoder HpackDecoder;

typedef struct{
    HeaderFieldIndexType (*policy)(void *u_data, const HttpHeaderField *header);
    void *u_data;
}IndexTypePolicy;

typedef enum{
    HpackStatusOk,

    HpackStatusFailedToParse,
    HpackStatusUnknwonHeaderFieldType,
    HpackStatusInvalidIndex
}HpackStatus;

HpackEncoder *hpack_encoder_new(size_t dynamic_table_size_bytes);
HpackDecoder *hpack_decoder_new(size_t dynamic_table_size_bytes);

void hpack_encoder_free(HpackEncoder *encoder);
void hpack_decoder_free(HpackDecoder *decoder);

HpackStatus hpack_decode_headers(HpackDecoder *decoder, ParseBuffer *parse_buffer, HttpHeaderField *headers, size_t max_header_count, size_t *actual_headers_count, Buffer *buffer);
size_t hpack_encode_headers_with_policy(HpackEncoder *encoder, const HttpHeaderField *headers, size_t header_count, Buffer *result, IndexTypePolicy policy);
size_t hpack_encode_headers(HpackEncoder *encoder, const HttpHeaderField *headers, size_t header_count, Buffer *result, HeaderFieldIndexType index_type);

void hpack_encoder_print_dynamic_headers(HpackEncoder *encoder);
void hpack_decoder_print_dynamic_headers(HpackDecoder *decoder);

#endif
