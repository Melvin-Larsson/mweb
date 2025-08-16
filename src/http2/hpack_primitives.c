#include "hpack_primitives.h"
#include "http2/huffman.h"
#include "http2_logging.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define BITMASK(n) ((1U << (n)) - 1U)
#define min(a, b) ((a) < (b) ? (a) : (b))

bool hpack_primitives_try_decode_int(ParseBuffer *buffer, uint8_t prefix_length, unsigned int *result){
    assert(prefix_length <= 8);

    if(buffer->parsed_size >= buffer->total_size){
        return false;
    }

    uint8_t prefix = BITMASK(prefix_length) & buffer->data[buffer->parsed_size];
    if(prefix < BITMASK(prefix_length)){
        buffer->parsed_size++;
        *result = prefix;
        return true;
    }

    int res = prefix;
    for(size_t i = 1; i < buffer->total_size - buffer->parsed_size; i++){
        res += (buffer->data[buffer->parsed_size + i] & ~(1 << 7)) << (i - 1) * 7;

        if((buffer->data[buffer->parsed_size + i] & (1 << 7)) == 0){
            buffer->parsed_size += i + 1;
            *result = res;
            return true;
        }
    }

    return false;
}

size_t hpack_primitives_encode_int(Buffer *buffer, uint8_t prefix_length, unsigned int value){
    assert(prefix_length <= 8);
    assert(buffer != NULL);
    assert(buffer->data != NULL);

    if(buffer->used_size >= buffer->total_size){
        return 0;
    }

    size_t initial_used_size = buffer->used_size;
    uint8_t *bytes = &buffer->data[buffer->used_size];
    if(value < BITMASK(prefix_length)){
        bytes[0] = (bytes[0] & ~BITMASK(prefix_length) | value);
        buffer->used_size++;
        return 1;
    }

    bytes[0] |= BITMASK(prefix_length);
    buffer->used_size++;
    value -= BITMASK(prefix_length);
    for(size_t i = 1; buffer->used_size < buffer->total_size; i++){
        buffer->used_size++;
        if(value >= 128){
            bytes[i] = (value & 0x7F) | (1 << 7);
            value >>= 7;
        }
        else{
            bytes[i] = value;
            return i + 1;
        }
    }

    return buffer->used_size - initial_used_size;
}

bool hpack_primitives_try_decode_string(ParseBuffer *buffer, Buffer *result, size_t *result_size){
    size_t initial_parsed_size = buffer->parsed_size;
    unsigned int str_length;
    if(!hpack_primitives_try_decode_int(buffer, 7, &str_length)){
        return false;
    }
    if(buffer->parsed_size + str_length > buffer->total_size){
        buffer->parsed_size = initial_parsed_size;
        return false;
    }

    bool is_huffman_encoded = (buffer->data[initial_parsed_size] & (1 << 7)) == 0 ? false : true;
    uint8_t *str_ptr = &buffer->data[buffer->parsed_size];
    size_t buffer_space = result->total_size - result->used_size;
    if(is_huffman_encoded){
        if(!huffman_decode(str_ptr, str_length * 8, &result->data[result->used_size], buffer_space, result_size)){
            buffer->parsed_size = initial_parsed_size;
            return false;
        }
        buffer->parsed_size += str_length;
        result->used_size += *result_size;
    }
    else{
        *result_size = min(buffer_space, str_length);
        memcpy(&result->data[result->used_size], str_ptr, *result_size);
        buffer->parsed_size += *result_size;
        result->used_size += *result_size;
    }

    return true;
}

size_t hpack_primitives_encode_string(Buffer *buffer, const char *str, size_t len){
    if(buffer->used_size >= buffer->total_size){
        return 0;
    }

    size_t initial_used_size = buffer->used_size;
    buffer->data[buffer->used_size] = 0;
    hpack_primitives_encode_int(buffer, 7, len);

    if(buffer->used_size >= buffer->total_size){
        return 0;
    }

    size_t actual_str_length = min(buffer->total_size - buffer->used_size, len);
    memcpy(&buffer->data[buffer->used_size], str, actual_str_length);
    buffer->used_size += actual_str_length;

    return buffer->used_size - initial_used_size;
}

HeaderFieldType hpack_primitives_get_header_field_type(const ParseBuffer *buffer){
    assert(buffer->total_size - buffer->parsed_size > 0);
    uint8_t *bytes = &buffer->data[buffer->parsed_size];

    if(bytes[0] >> 7 == 1){
        return HeaderFieldIndexed;
    }
    if(bytes[0] >> 6 == 0b01 && (bytes[0] & 0b111111) != 0
            || bytes[0] >> 4 == 0 && (bytes[0] & 0b1111) != 0
            || bytes[0] >> 4 == 0b1 && (bytes[0] & 0b1111) != 0){
        return HeaderFieldLiteralFieldIndexedName;
    }
    else if(bytes[0] >> 6 == 0b01 && (bytes[0] & 0b111111) == 0
            || bytes[0] >> 4 == 0 && (bytes[0] & 0b1111) == 0
            || bytes[0] >> 4 == 0b1 && (bytes[0] & 0b1111) == 0){
        return HeaderFieldLiteralFieldNewName;
    }

    return HeaderFieldUnknown;
}

HeaderFieldIndexType hpack_primitives_get_header_field_index_type(const ParseBuffer *buffer){
    assert(buffer->total_size - buffer->parsed_size > 0);
    HeaderFieldType type = hpack_primitives_get_header_field_type(buffer);
    assert(type == HeaderFieldLiteralFieldIndexedName || type == HeaderFieldLiteralFieldNewName);

    if(buffer->data[buffer->parsed_size] >> 6 == 0b01){
        return IndexTypeIncremental;
    }
    if (buffer->data[buffer->parsed_size] >> 4 == 0){
        return IndexTypeWithout;
    }
    if (buffer->data[buffer->parsed_size] >> 4 == 0b1){
        return IndexTypeNever;
    }

    return IndexTypeUnknown;
}

size_t hpack_primitives_encode_header_field(HeaderFieldIndexType type, unsigned int index, Buffer *result){
    if(result->used_size >= result->total_size){
        return 0;
    }
    switch(type){
        case IndexTypeIncremental:
            result->data[result->used_size] = 0b01000000;
            return hpack_primitives_encode_int(result, 6, index);
        case IndexTypeWithout:
            result->data[result->used_size] = 0;
            return hpack_primitives_encode_int(result, 4, index);
        case IndexTypeNever:
            result->data[result->used_size] = 0b00010000;
            return hpack_primitives_encode_int(result, 4, index);
        case IndexTypeUnknown:
            assert(false);
    }
}

bool hpack_primitives_try_decode_indexed_header_field(ParseBuffer *buffer, HpackHeaderFieldIndexed *result){
    assert(hpack_primitives_get_header_field_type(buffer) == HeaderFieldIndexed);

    if(!hpack_primitives_try_decode_int(buffer, 7, &result->index)){
        return false;
    }
    return true;
}
size_t hpack_primitives_encode_indexed_header_field(const HpackHeaderFieldIndexed *field, Buffer *result){
    if(result->used_size >= result->total_size){
        return 0;
    }

    result->data[result->used_size] = 0x80;
    return hpack_primitives_encode_int(result, 7, field->index);
}

bool hpack_primitives_try_decode_literal_field_indexed_name(ParseBuffer *buffer, HpackHeaderLiteralFieldIndexedName *result, Buffer *field_buffer){
    assert(hpack_primitives_get_header_field_type(buffer) == HeaderFieldLiteralFieldIndexedName);

    size_t initial_parsed_size = buffer->parsed_size;
    result->index_type = hpack_primitives_get_header_field_index_type(buffer);
    if(result->index_type == IndexTypeUnknown){
        ERROR("Unknown index type");
        return false;
    }

    if(!hpack_primitives_try_decode_int(buffer, 6, &result->index)){
        ERROR("Unable to decode index");
        return false;
    }

    result->value = (char *)&field_buffer->data[field_buffer->used_size];
    if(!hpack_primitives_try_decode_string(buffer, field_buffer, &result->value_length)){
        ERROR("Unable to decode string");
        buffer->parsed_size = initial_parsed_size;
        return false;
    }

    return true;
}
size_t hpack_primitives_encode_literal_field_indexed_name(const HpackHeaderLiteralFieldIndexedName *header, Buffer *result){
    size_t size = hpack_primitives_encode_header_field(header->index_type, header->index, result);
    size += hpack_primitives_encode_string(result, header->value, header->value_length);
    return size;
}

bool hpack_primitives_try_decode_literal_field_new_name(ParseBuffer *buffer, HpackHeaderLiteralFieldNewName *result, Buffer *field_buffer){
    assert(hpack_primitives_get_header_field_type(buffer) == HeaderFieldLiteralFieldNewName);

    size_t initial_parsed_size = buffer->parsed_size;
    size_t initial_field_buffer_used_size = field_buffer->used_size;
    result->index_type = hpack_primitives_get_header_field_index_type(buffer);
    if(result->index_type == IndexTypeUnknown){
        return false;
    }

    buffer->parsed_size++;
    result->name = (char *)&field_buffer->data[field_buffer->used_size];
    if(!hpack_primitives_try_decode_string(buffer, field_buffer, &result->name_length)){
        buffer->parsed_size = initial_parsed_size;
        return false;
    }

    result->value = (char *)&field_buffer->data[field_buffer->used_size];
    if(!hpack_primitives_try_decode_string(buffer, field_buffer, &result->value_length)){
        buffer->parsed_size = initial_parsed_size;
        field_buffer->used_size = initial_field_buffer_used_size;
        return false;
    }

    return true;
}
size_t hpack_primitives_encode_literal_field_new_name(const HpackHeaderLiteralFieldNewName *header, Buffer *result){
    size_t size = hpack_primitives_encode_header_field(header->index_type, 0, result);
    size += hpack_primitives_encode_string(result, header->name, header->name_length);
    size += hpack_primitives_encode_string(result, header->value, header->value_length);
    return size;
}
