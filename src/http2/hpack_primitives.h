#ifndef HPACK_PRIMITIVES
#define HPACK_PRIMITIVES

#include <stddef.h>
#include "stdbool.h"
#include <stdint.h>
#include "buffers.h"

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

size_t hpack_primitives_encode_int(Buffer *buffer, uint8_t prefix_length, unsigned int value);
bool hpack_primitives_try_decode_int(ParseBuffer *buffer, uint8_t prefix_length, unsigned int *result);

size_t hpack_primitives_encode_string(Buffer *buffer, const char *str, size_t len);
bool hpack_primitives_try_decode_string(ParseBuffer *buffer, Buffer *result_buffer, size_t *result_size);

HeaderFieldType hpack_primitives_get_header_field_type(const ParseBuffer *buffer);
HeaderFieldIndexType hpack_primitives_get_header_field_index_type(const ParseBuffer *buffer);
size_t hpack_primitives_encode_header_field(HeaderFieldIndexType type, unsigned int index, Buffer *result);

bool hpack_primitives_try_decode_indexed_header_field(ParseBuffer *buffer, HpackHeaderFieldIndexed *result);
size_t hpack_primitives_encode_indexed_header_field(const HpackHeaderFieldIndexed *field, Buffer *result);

bool hpack_primitives_try_decode_literal_field_new_name(ParseBuffer *buffer, HpackHeaderLiteralFieldNewName *result, Buffer *field_buffer);
size_t hpack_primitives_encode_literal_field_new_name(const HpackHeaderLiteralFieldNewName *header, Buffer *result);

bool hpack_primitives_try_decode_literal_field_indexed_name(ParseBuffer *buffer, HpackHeaderLiteralFieldIndexedName *result, Buffer *field_buffer);
size_t hpack_primitives_encode_literal_field_indexed_name(const HpackHeaderLiteralFieldIndexedName *header, Buffer *result);

#endif
