#include "hpack.h"
#include "buffers.h"
#include "hpack_primitives.h"
#include "http2_logging.h"
#include <assert.h>
#include <stdlib.h>
#include "hpack_table.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef struct{
    uint16_t offset;
    uint16_t name_length;
    uint16_t value_length;
}HeaderFieldEntry;

typedef struct{
    char *dynamic_table_data;
    size_t dynamic_table_enqueue;
    size_t dynamic_table_size_bytes;

    HeaderFieldEntry *dynamic_table;
    size_t dynamic_table_entry_count;
}HpackCtx;

struct HpackEncoder{
    HpackCtx ctx;
};

struct HpackDecoder{
    HpackCtx ctx;
};

static bool _init_ctx(HpackCtx *ctx, size_t dynamic_table_size_bytes);
static void _deinit_ctx(HpackCtx *ctx);

HpackEncoder *hpack_encoder_new(size_t dynamic_table_size_bytes){
    HpackEncoder *encoder = malloc(sizeof(HpackEncoder));
    if(encoder == NULL){
        return NULL;
    }
    _init_ctx(&encoder->ctx, dynamic_table_size_bytes);
    return encoder;
}

HpackDecoder *hpack_decoder_new(size_t dynamic_table_size_bytes){
    HpackDecoder *decoder = malloc(sizeof(HpackDecoder));
    if(decoder == NULL){
        return NULL;
    }
    if(!_init_ctx(&decoder->ctx, dynamic_table_size_bytes)){
        free(decoder);
        return NULL;
    }
    return decoder;
}

static bool _init_ctx(HpackCtx *ctx, size_t dynamic_table_size_bytes){
    char *data = malloc(dynamic_table_size_bytes);
    HeaderFieldEntry *dynamic_table = malloc(dynamic_table_size_bytes / 32 * sizeof(HeaderFieldEntry));
    if(data == NULL || dynamic_table == 0){
        goto exit_ctx;
    }

    *ctx = (HpackCtx){
        .dynamic_table_data = data,
        .dynamic_table_enqueue = 0,
        .dynamic_table_size_bytes = dynamic_table_size_bytes,
        .dynamic_table = dynamic_table,
        .dynamic_table_entry_count = 0,
    };

    return true;
exit_ctx:
    free(data);
    free(dynamic_table);
    return false;
}

static void _deinit_ctx(HpackCtx *ctx){
    if(ctx == NULL){
        return;
    }

    free(ctx->dynamic_table);
    free(ctx->dynamic_table_data);
}

void hpack_encoder_free(HpackEncoder *encoder){
    if(encoder == NULL){
        return;
    }
    _deinit_ctx(&encoder->ctx);
    free(encoder);
}

void hpack_decoder_free(HpackDecoder *decoder){
    if(decoder == NULL){
        return;
    }
    _deinit_ctx(&decoder->ctx);
    free(decoder);
}

void _copy_to_circular_array(char *dst, size_t dst_size, const char *src, size_t src_size, size_t offset){
    assert(src_size <= dst_size);

    offset = offset % dst_size;

    size_t size_before_wrap = dst_size - offset; 
    memcpy(dst + offset, src, min(size_before_wrap, src_size));

    if(src_size > size_before_wrap){
        memcpy(dst, src + size_before_wrap, src_size - size_before_wrap);
    }
}

void _copy_from_circular_array(char *dst, size_t dst_size, const char *src, size_t src_size, size_t offset){
    assert(dst_size <= src_size);

    offset = offset % src_size;

    size_t size_before_wrap = src_size - offset; 
    memcpy(dst, src + offset, min(size_before_wrap, dst_size));

    if(dst_size > size_before_wrap){
        memcpy(dst + size_before_wrap, src, dst_size - size_before_wrap);
    }
}

void _dynamic_table_add(HpackCtx *ctx, const HttpHeaderField *header){
    size_t new_offset = ctx->dynamic_table_enqueue;
    size_t new_size = header->name_length + header->value_length + 32;


    size_t name_offset = new_offset;
    size_t value_offset = (new_offset + header->name_length) % ctx->dynamic_table_size_bytes;
    _copy_to_circular_array(ctx->dynamic_table_data, ctx->dynamic_table_size_bytes, header->name, header->name_length, name_offset);
    _copy_to_circular_array(ctx->dynamic_table_data, ctx->dynamic_table_size_bytes, header->value, header->value_length, value_offset);
    ctx->dynamic_table_enqueue = (new_offset + new_size) % ctx->dynamic_table_size_bytes;

    size_t evict_count = 0;
    for(size_t i = 0; i < ctx->dynamic_table_entry_count; i++){
        size_t old_offset = ctx->dynamic_table[i].offset;
        size_t old_size = ctx->dynamic_table[i].name_length + ctx->dynamic_table[i].value_length + 32;

        size_t end_old = (old_offset + old_size) % ctx->dynamic_table_size_bytes;
        size_t end_new = (new_offset + new_size) % ctx->dynamic_table_size_bytes;

        bool overlap = false;
        if (new_offset <= end_new) {
            overlap = (old_offset >= new_offset && old_offset < end_new);
        } else {
            overlap = (old_offset >= new_offset || old_offset < end_new);
        }

        if(overlap){
            evict_count++;
        }
    }
    memmove(ctx->dynamic_table, &ctx->dynamic_table[evict_count], ctx->dynamic_table_entry_count * sizeof(HeaderFieldEntry));
    ctx->dynamic_table_entry_count -= evict_count;

    ctx->dynamic_table[ctx->dynamic_table_entry_count++] = (HeaderFieldEntry){
        .name_length = header->name_length,
        .value_length = header->value_length,
        .offset = new_offset
    };
}

bool _try_get_header(HpackCtx *ctx, unsigned int index, HttpHeaderField *result, Buffer *buffer, bool only_name){
    if(index == 0){
        return false;
    }
    if(index >= 1 && index <= 61){
        HttpHeaderField field = static_table[index - 1];

        result->name = (char *)&buffer->data[buffer->used_size];
        result->name_length = buffers_append(buffer, (uint8_t *)field.name, field.name_length);

        if(!only_name){
            result->value = (char *)&buffer->data[buffer->used_size];
            result->value_length = buffers_append(buffer, (uint8_t *)field.value, field.value_length);
        }

        return true;
    }

    index -= 62;
    if(index < ctx->dynamic_table_entry_count){
        HeaderFieldEntry entry = ctx->dynamic_table[ctx->dynamic_table_entry_count - index - 1];
        size_t space_left = buffer->total_size - buffer->used_size;
        size_t copy_size = min(entry.name_length, space_left);
        result->name = (char *)&buffer->data[buffer->used_size];
        result->name_length = copy_size;
        _copy_from_circular_array((char *)&buffer->data[buffer->used_size], copy_size, ctx->dynamic_table_data, ctx->dynamic_table_size_bytes, entry.offset);
        buffer->used_size += copy_size;

        if(!only_name){
            space_left = buffer->total_size - buffer->used_size;
            copy_size = min(entry.value_length, space_left);
            result->value = (char *)&buffer->data[buffer->used_size];
            result->value_length = copy_size;
            _copy_from_circular_array((char *)&buffer->data[buffer->used_size], copy_size, ctx->dynamic_table_data, ctx->dynamic_table_size_bytes, entry.offset + entry.name_length);
            buffer->used_size += copy_size;
        }

         return true;
    }

    return false;
}
void _print_dynamic_headers(HpackCtx *ctx){
    printf("Printing %zu headers\n", ctx->dynamic_table_entry_count);
    for(size_t i = 0; i < ctx->dynamic_table_entry_count; i++){
        uint8_t buff[1024];
        Buffer buffer;
        buffers_init_buffer(&buffer, buff, sizeof(buff));
        HttpHeaderField header;
        _try_get_header(ctx, i + 62, &header, &buffer, false);
        printf("%d: ", i + 62);
        for(size_t j = 0; j < header.name_length; j++){
            printf("%c", header.name[j]);
        }
        printf(": ");
        for(size_t j = 0; j < header.value_length; j++){
            printf("%c", header.value[j]);
        }
        printf("\n");
    }
}

void hpack_encoder_print_dynamic_headers(HpackEncoder *encoder){
    _print_dynamic_headers(&encoder->ctx);
}
void hpack_decoder_print_dynamic_headers(HpackDecoder *decoder){
    _print_dynamic_headers(&decoder->ctx);
}


void _print_header(HttpHeaderField *header){
    for(size_t i = 0; i < header->name_length; i++){
        printf("%c", header->name[i]);
    }
    printf(": ");
    for(size_t i = 0; i < header->value_length; i++){
        printf("%c", header->value[i]);
    }
    printf("\n");
}

HpackStatus hpack_decode_headers(
        HpackDecoder *decoder,
        ParseBuffer *parse_buffer,
        HttpHeaderField *headers,
        size_t max_header_count,
        size_t *actual_headers_count,
        Buffer *buffer
    ){
    HpackStatus status = HpackStatusOk;
    *actual_headers_count = 0;

    size_t initial_parsed_size = parse_buffer->parsed_size;
    size_t initial_used_size = buffer->used_size;
    while(parse_buffer->parsed_size < parse_buffer->total_size && *actual_headers_count < max_header_count){
        HeaderFieldType type = hpack_primitives_get_header_field_type(parse_buffer);
        switch(type){
            case HeaderFieldIndexed:
                {
                    HttpHeaderField *http_header = &headers[(*actual_headers_count)++];
                    HpackHeaderFieldIndexed header;
                    if(!hpack_primitives_try_decode_indexed_header_field(parse_buffer, &header)){
                        ERROR("Unable to parse indexed header field");
                        status = HpackStatusFailedToParse;
                        goto exit_failure;
                    }

                    if(!_try_get_header(&decoder->ctx, header.index, http_header, buffer, false)){
                        status = HpackStatusInvalidIndex;
                        ERROR("Unable to find header %d", header.index);
                        goto exit_failure;
                    }
//                     printf("Fetched indexed\n");;
//                     for(size_t i = 0; i < buffer.used_size; i++){
//                         printf("%c", buffer.data[i]);
//                     }
//                     printf("\n");
                }
                break;
            case HeaderFieldLiteralFieldIndexedName:
                {
                    HttpHeaderField *http_header = &headers[(*actual_headers_count)++];
                    HeaderFieldIndexType index_type = hpack_primitives_get_header_field_index_type(parse_buffer);

                    HpackHeaderLiteralFieldIndexedName header;
                    if(!hpack_primitives_try_decode_literal_field_indexed_name(parse_buffer, &header, buffer)){
                        status = HpackStatusFailedToParse;
                        ERROR("Unable to parse literal field with indexed name");
                        goto exit_failure;
                    }
                    http_header->value = header.value;
                    http_header->value_length = header.value_length;

                    if(!_try_get_header(&decoder->ctx, header.index, http_header, buffer, true)){
                        ERROR("Unable to find header %d", header.index);
                        status = HpackStatusInvalidIndex;
                        goto exit_failure;
                    }

                    if(index_type == IndexTypeIncremental){
                        _dynamic_table_add(&decoder->ctx, http_header);
//                         _print_dynamic_headers(ctx);
                    }
                    break;
                }
            case HeaderFieldLiteralFieldNewName:
                {
                    HttpHeaderField *http_header = &headers[(*actual_headers_count)++];
                    HeaderFieldIndexType index_type = hpack_primitives_get_header_field_index_type(parse_buffer);

                    HpackHeaderLiteralFieldNewName header;
                    if(!hpack_primitives_try_decode_literal_field_new_name(parse_buffer, &header, buffer)){
                        ERROR("Unable to parse literal field with new name");
                        status = HpackStatusFailedToParse;
                        goto exit_failure;
                    }
                    *http_header = (HttpHeaderField){
                        .name = header.name,
                        .name_length = header.name_length,
                        .value = header.value,
                        .value_length = header.value_length
                    };

                    if(index_type == IndexTypeIncremental){
                        _dynamic_table_add(&decoder->ctx, http_header);
//                         _print_dynamic_headers(ctx);
                    }
                }
                break;
            default:
                status = HpackStatusUnknwonHeaderFieldType;
                ERROR("Received unknown header field type");
                goto exit_failure;
        }

    }

    return HpackStatusOk;

exit_failure:
    ERROR("Failed when parsing: ");
    for(size_t i = initial_parsed_size; i < parse_buffer->parsed_size; i++){
        printf("%X ", parse_buffer->data[i]);
    }
    printf("\n");
    parse_buffer->parsed_size = initial_parsed_size;
    buffer->used_size = initial_used_size;
    *actual_headers_count = 0;
    return status;
}

bool _headers_equals_name(const HttpHeaderField *h1, const HttpHeaderField *h2){
    return h1->name_length == h2->name_length && memcmp(h1->name, h2->name, h2->name_length) == 0;
}

bool _headers_equals_value(const HttpHeaderField *h1, const HttpHeaderField *h2){
    return h1->value_length == h2->value_length && memcmp(h1->value, h2->value, h2->value_length) == 0;
}

bool _headers_equals_exact(const HttpHeaderField *h1, const HttpHeaderField *h2){
    return _headers_equals_name(h1, h2) && _headers_equals_value(h1, h2);
}

char *_dynamic_table_get(HpackCtx *ctx, size_t offset, size_t size, Buffer *buffer){
    size_t actual_size = min(size, buffer_size_left(buffer));
    char *result = (char *)buffer_get_append_ptr(buffer);
     _copy_from_circular_array(result, actual_size, ctx->dynamic_table_data, ctx->dynamic_table_size_bytes, offset);

     return result;
}

HttpHeaderField _header_field_entry_to_field(HpackCtx *ctx, HeaderFieldEntry *entry, Buffer *buffer){
    return (HttpHeaderField){
        .name = _dynamic_table_get(ctx, entry->offset, entry->name_length, buffer),
        .name_length = entry->name_length,
        .value = _dynamic_table_get(ctx, entry->offset, entry->name_length, buffer),
        .value_length = entry->value_length
    };
}

ssize_t _get_table_index_with_comparitor(HpackCtx *ctx, const HttpHeaderField *header, bool (*equals)(const HttpHeaderField *h1, const HttpHeaderField *h2)){
    for(size_t i = 0; i < 61; i++){
        const HttpHeaderField *entry = &static_table[i];
        if(equals(header, entry)){
            return i + 1;
        }
    }

    for(size_t i = 0; i < ctx->dynamic_table_entry_count; i++){
        uint8_t buff[4096];
        Buffer buffer;
        buffers_init_buffer(&buffer, buff, sizeof(buff));

        HttpHeaderField entry = _header_field_entry_to_field(ctx, &ctx->dynamic_table[i], &buffer);
        assert(!buffer_size_is_full(&buffer));
        if(equals(header, &entry)){
            return i + 1;
        }
    }   

    return -1;
}

ssize_t _get_table_index_name_match(HpackCtx *ctx, const HttpHeaderField *header){
    return _get_table_index_with_comparitor(ctx, header, _headers_equals_name);
}
ssize_t _get_table_index_exact_match(HpackCtx *ctx, const HttpHeaderField *header){
    return _get_table_index_with_comparitor(ctx, header, _headers_equals_exact);
}

size_t hpack_encode_headers_with_policy(HpackEncoder *encoder, const HttpHeaderField *headers, size_t header_count, Buffer *result, IndexTypePolicy policy){
    size_t initial_used_size = result->used_size;
    for(size_t i = 0; i < header_count; i++){
        ssize_t exact_match_index = _get_table_index_exact_match(&encoder->ctx, &headers[i]);
        if(exact_match_index > 0){
            HpackHeaderFieldIndexed indexed_header = {
                .index = exact_match_index
            };
            hpack_primitives_encode_indexed_header_field(&indexed_header, result);
            continue;
        }

        ssize_t name_match_index = _get_table_index_name_match(&encoder->ctx, &headers[i]);
        HeaderFieldIndexType index_type = policy.policy(policy.u_data, &headers[i]);
        assert(index_type != IndexTypeUnknown);
        if(name_match_index > 0){
            HpackHeaderLiteralFieldIndexedName indexed_name_header = {
                .index = name_match_index,
                .value = headers[i].value,
                .value_length = headers[i].value_length,
                .index_type = index_type
            };
            hpack_primitives_encode_literal_field_indexed_name(&indexed_name_header, result);
        }
        else{
            HpackHeaderLiteralFieldNewName new_name_header = {
                .name = headers[i].name,
                .name_length = headers[i].name_length,
                .value = headers[i].value,
                .value_length = headers[i].value_length,
                .index_type = index_type
            };
            hpack_primitives_encode_literal_field_new_name(&new_name_header, result);
        }

        if(index_type == IndexTypeIncremental){
            _dynamic_table_add(&encoder->ctx, &headers[i]);
        }
    }

    return result->used_size - initial_used_size;
}

HeaderFieldIndexType _policy(void *data, const HttpHeaderField *header){
    return *((HeaderFieldIndexType *)data);
}

size_t hpack_encode_headers(HpackEncoder *encoder, const HttpHeaderField *headers, size_t header_count, Buffer *result, HeaderFieldIndexType index_type){
    IndexTypePolicy policy = {_policy, &index_type};
    return hpack_encode_headers_with_policy(encoder, headers, header_count, result, policy);
}
