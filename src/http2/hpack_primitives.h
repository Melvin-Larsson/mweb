#ifndef HPACK_PRIMITIVES
#define HPACK_PRIMITIVES

#include <stddef.h>
#include "stdbool.h"
#include <stdint.h>

typedef enum{
    HeaderFieldUnknown,
    HeaderFieldIndexed,
    HeaderFieldLiteralFieldIndexedName,
    HeaderFieldLiteralFieldNewName,

    DynamicTableSizeUpdate, //Correct?
}HeaderFieldType;

typedef enum{
    IndexTypeUnknown,
    IndexTypeIncremental,
    IndexTypeWithout,
    IndexTypeNever,
}HeaderFieldIndexType;

typedef struct{
    unsigned int index;
}HpackHeaderFieldIndexed;

typedef struct{
    HeaderFieldIndexType index_type;
    unsigned int index;
    char *value;
    size_t value_length;
}HpackHeaderLiteralFieldIndexedName;

typedef struct{
    HeaderFieldIndexType index_type;
    char *name;
    size_t name_length;
    char *value;
    size_t value_length;
}HpackHeaderLiteralFieldNewName;

size_t hpack_primitives_encode_int(unsigned char *bytes, size_t size, uint8_t prefix_length, unsigned int value);
bool hpack_primitives_try_decode_int(unsigned char *bytes, size_t size, uint8_t prefix_length, unsigned int *result);
size_t hpack_primitives_get_int_length(unsigned int value, uint8_t prefix_length);

size_t hpack_primitives_encode_string(const char *str, size_t len, char *buffer, size_t buffer_size);
bool hpack_primitives_try_decode_string(char *bytes, size_t size, char *result, size_t max_result_size, size_t *actual_result_size);

HeaderFieldType hpack_primitives_get_header_field_type(char *bytes, size_t size);

HeaderFieldType hpack_primitives_get_header_field_type(char *bytes, size_t size);
HeaderFieldIndexType hpack_primitives_get_header_field_index_type(char *bytes, size_t size);

bool hpack_primitives_try_decode_indexed_header_field(char *bytes, size_t size, HpackHeaderFieldIndexed *result, size_t *used_size);
bool hpack_primitives_try_decode_liternal_field_new_name(char *bytes, size_t size, HpackHeaderLiteralFieldNewName *result, size_t *used_size);
bool hpack_primitives_try_decode_liternal_field_indexed_name(char *bytes, size_t size, HpackHeaderLiteralFieldIndexedName *result, size_t *used_size);
#endif
