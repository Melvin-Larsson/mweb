#include "hpack_primitives.h"
#include "http2/http2_logging.h"
#include "http2/huffman.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define BITMASK(n) ((1U << (n)) - 1U)
#define min(a, b) ((a) < (b) ? (a) : (b))

bool hpack_primitives_try_decode_int(unsigned char *bytes, size_t size, uint8_t prefix_length, unsigned int *result){
    assert(prefix_length <= 8);

    uint8_t prefix = BITMASK(prefix_length) & bytes[0];
    if(prefix < BITMASK(prefix_length)){
        *result = prefix;
        return true;
    }

    int res = prefix;
    for(size_t i = 1; i < size; i++){
        res += (bytes[i] & ~(1 << 7)) << (i - 1) * 7;

        if((bytes[i] & (1 << 7)) == 0){
            *result = res;
            return true;
        }
    }
    return false;
}

size_t hpack_primitives_encode_int(unsigned char *bytes, size_t size, uint8_t prefix_length, unsigned int value){
    assert(prefix_length <= 8);
    assert(bytes != NULL);

    if(size == 0){
        return 0;
    }

    if(value < BITMASK(prefix_length)){
        bytes[0] = (bytes[0] & ~BITMASK(prefix_length) | value);
        return 1;
    }

    bytes[0] |= BITMASK(prefix_length);
    value -= BITMASK(prefix_length);
    for(size_t i = 1; i < size; i++){
        if(value >= 128){
            bytes[i] = (value & 0x7F) | (1 << 7);
            value >>= 7;
        }
        else{
            bytes[i] = value;
            return i + 1;
        }
    }

    return size;
}

size_t hpack_primitives_get_int_length(unsigned int value, uint8_t prefix_length){
    unsigned char buff[64];
    size_t size = hpack_primitives_encode_int(buff, sizeof(buff), prefix_length, value);
    assert(size != sizeof(buff) && "Too little buffer space to encode int");
    return size;
}

bool hpack_primitives_try_decode_string(char *bytes, size_t size, char *result, size_t max_result_size, size_t *actual_result_size){
    unsigned int str_length;
    if(!hpack_primitives_try_decode_int((unsigned char *)bytes, size, 7, &str_length)){
        return false;
    }

    unsigned char buff[64];
    size_t length_field_size = hpack_primitives_encode_int(buff, sizeof(buff), 7, str_length);
    if(length_field_size == sizeof(buff)){
        ERROR("Unexpected length for field");
        return false;
    }

    if(str_length + length_field_size > size){
        return false;
    }

    char *str_ptr = bytes + length_field_size;

    bool is_huffman_encoded = (bytes[0] & (1 << 7)) == 0 ? false : true;
    if(is_huffman_encoded){
        printf("is huffman\n");
        return huffman_decode(str_ptr, str_length * 8, result, max_result_size, actual_result_size);
    }
    else{
        *actual_result_size = min(max_result_size, str_length);
        memcpy(result, str_ptr, *actual_result_size);
    }

    return true;
}

size_t hpack_primitives_encode_string(const char *str, size_t len, char *buffer, size_t buffer_size){
    if(buffer_size == 0){
        return 0;
    }
    *buffer = 0;
    size_t length_field_size = hpack_primitives_encode_int((unsigned char *)buffer, buffer_size, 7, len);

    if(length_field_size >= buffer_size){
        return length_field_size;
    }

    size_t actual_str_length = min(buffer_size - length_field_size, len);
    memcpy(buffer + length_field_size, str, actual_str_length);

    return length_field_size + actual_str_length;
}

HeaderFieldType hpack_primitives_get_header_field_type(char *bytes, size_t size){
    assert(size > 0);

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

HeaderFieldIndexType hpack_primitives_get_header_field_index_type(char *bytes, size_t size){
    assert(size > 0);
    HeaderFieldType type = hpack_primitives_get_header_field_type(bytes, size);
    assert(type == HeaderFieldLiteralFieldNewName || type == HeaderFieldLiteralFieldNewName);

    if(bytes[0] >> 6 == 0b01){
        return IndexTypeIncremental;
    }
    if (bytes[0] >> 4 == 0){
        return IndexTypeWithout;
    }
    if (bytes[0] >> 4 == 0b1){
        return IndexTypeNever;
    }

    return IndexTypeUnknown;
}

bool hpack_primitives_try_decode_indexed_header_field(char *bytes, size_t size, HpackHeaderFieldIndexed *result, size_t *used_size){
    assert(hpack_primitives_get_header_field_type(bytes, size) == HeaderFieldIndexed);

    if(!hpack_primitives_try_decode_int((uint8_t *)bytes, size, 7, &result->index)){
        return false;
    }
    used_size = hpack_primitives_get_int_length(result->index, 7);
    return true;
}

bool hpack_primitives_try_decode_liternal_field_indexed_name(char *bytes, size_t size, HpackHeaderLiteralFieldIndexedName *result, size_t *used_size){
    assert(hpack_primitives_get_header_field_type(bytes, size) == HeaderFieldLiteralFieldIndexedName);

    result->index_type = hpack_primitives_get_header_field_index_type(bytes, size);
    if(result->index_type == IndexTypeUnknown){
        return false;
    }

    if(!hpack_primitives_try_decode_int((uint8_t *)bytes, size, 6, &result->index)){
        return false;
    }
    size_t int_length = hpack_primitives_get_int_length(result->index, 6);

    if(size <= int_length){
        return false;
    }

    char buff[1024];
    if(!hpack_primitives_try_decode_string(bytes + int_length, size - int_length, buff, sizeof(buff), &result->value_length)){
        return false;
    }
    if(result->value_length == sizeof(buff)){
        return false;
    }

    result->value = malloc(result->value_length);
    if(!result->value){
        return false;
    }
    memcpy(result->value, buff, result->value_length);

    return true;
}

bool hpack_primitives_try_decode_liternal_field_new_name(char *bytes, size_t size, HpackHeaderLiteralFieldNewName *result){
    assert(hpack_primitives_get_header_field_type(bytes, size) == HeaderFieldLiteralFieldNewName);

    result->index_type = hpack_primitives_get_header_field_index_type(bytes, size);
    if(result->index_type == IndexTypeUnknown){
        return false;
    }

    char buff[1024];
    if(!hpack_primitives_try_decode_string(bytes + 1, size - 1, buff, sizeof(buff), &result->name_length)){
        return false;
    }
    if(result->name_length == sizeof(buff)){
        return false;
    }
    result->name = malloc(result->name_length);
    if(!result->name){
        return false;
    }
    memcpy(result->name, buff, result->name_length);

    if(!hpack_primitives_try_decode_string(bytes + 1 + result->name_length, size - 1 - result->name_length, buff, sizeof(buff), &result->value_length)){
        free(result->name);
        return false;
    }
    if(result->value_length == sizeof(buff)){
        free(result->name);
        return false;
    }
    result->value = malloc(result->value_length);
    if(!result->value){
        free(result->name);
        return false;
    }
    memcpy(result->value, buff, result->value_length);

    return true;
}
