#include "http2/hpack.h"
#include "test_harness.h"
#include "http2/huffman.h"
#include "http2/hpack_primitives.h"
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define min(a, b) ((a) < (b) ? (a) : (b))

static void _print_bytes(char *buff, size_t size){
    for(size_t i = 0; i < size; i++){
        printf("%X ", (uint8_t)buff[i]);
    }
    printf("\n");
}

bool _test_int_encode_decode(unsigned int value, uint8_t prefix){
    unsigned char buff[128];
    memset(buff, 0xFF, sizeof(buff));

    Buffer buffer;
    buffers_init_buffer(&buffer, buff, sizeof(buff));

    size_t len = hpack_primitives_encode_int(&buffer, prefix, value); 

    unsigned int decoded;
    ParseBuffer parse_buffer = {.data = buff, 0, sizeof(buff)};
    bool status = hpack_primitives_try_decode_int(&parse_buffer, prefix, &decoded); 

    ASSERT_SIZE_EQUAL(sizeof(buff), buffer.total_size);
    ASSERT_SIZE_EQUAL(len, buffer.used_size);
    ASSERT_SIZE_EQUAL(sizeof(buff), parse_buffer.total_size);
    ASSERT_SIZE_EQUAL(len, parse_buffer.parsed_size);
    ASSERT_INT_EQUAL(status, true);
    ASSERT_INT_EQUAL(value, decoded);

    return true;
}


bool _test_str_encode_no_huffman(size_t count){
    assert(count <= 64);
    uint8_t str[64];
    uint8_t encoded[128];
    uint8_t decoded[64];

    Buffer encode_buffer;
    buffers_init_buffer(&encode_buffer, encoded, sizeof(encoded));
    size_t encoded_size = hpack_primitives_encode_string(&encode_buffer, (char *)str, count);

    size_t decoded_size;
    ParseBuffer buffer;
    Buffer result_buffer;
    buffers_init_parse_buffer(&buffer, encoded, sizeof(encoded));
    buffers_init_buffer(&result_buffer, decoded, sizeof(decoded));

    bool status = hpack_primitives_try_decode_string(&buffer, &result_buffer, &decoded_size); 

    ASSERT_INT_EQUAL(true, status);

    ASSERT_SIZE_EQUAL(sizeof(encoded), buffer.total_size);
    ASSERT_SIZE_EQUAL(encoded_size, buffer.parsed_size);
    ASSERT_SIZE_EQUAL(count, decoded_size);

    ASSERT_SIZE_EQUAL(sizeof(decoded), result_buffer.total_size);
    ASSERT_SIZE_EQUAL(count, result_buffer.used_size);

    ASSERT_BYTES_EQUAL(str, count, result_buffer.data, decoded_size);

    return true;
}

bool encode_decode_int_1_prefix_1(){
    return _test_int_encode_decode(1, 1);
}

bool encode_decode_int_2_prefix_1(){
    return _test_int_encode_decode(2, 1);
}

bool encode_decode_int_129_prefix_1(){
    return _test_int_encode_decode(129, 1);
}

bool encode_decode_int_0_to_million_all_prefixes(){
    unsigned char buff[128];
    for(int prefix = 1; prefix <= 8; prefix++){
        for(unsigned int value = 0; value < 1000000; value++){
            if(!_test_int_encode_decode(value, prefix)){
                return false;
            }
        }
    }

    return true;
}

bool encode_decode_uint_max_all_prefixes(){
    unsigned char buff[128];
    for(int prefix = 1; prefix <= 8; prefix++){
        if(!_test_int_encode_decode(UINT_MAX, prefix)){
            return false;
        }
    }

    return true;
}

bool encode_decode_str_len_3(){
    return _test_str_encode_no_huffman(3);
}

bool encode_decode_str_len_0_to_64(){
    for(size_t i = 0; i < 64; i++){
        if(!_test_str_encode_no_huffman(i)){
            return false;
        }
    }
    return true;
}
 
bool decode_huffman_str(){
    uint8_t bytes[] = {0b10000011, 0b00111001, 0b11001110, 0b01111111};
    char result[128];

    ParseBuffer buffer;
    Buffer result_buffer;
    buffers_init_parse_buffer(&buffer, bytes, sizeof(bytes));
    buffers_init_buffer(&result_buffer, result, sizeof(result));

    size_t actual_size;
    bool success = hpack_primitives_try_decode_string(&buffer, &result_buffer, &actual_size);

    ASSERT_INT_EQUAL(true, success);

    ASSERT_SIZE_EQUAL(sizeof(bytes), buffer.total_size);
    ASSERT_SIZE_EQUAL(sizeof(bytes), buffer.parsed_size);
    ASSERT_SIZE_EQUAL(sizeof(result), result_buffer.total_size);
    ASSERT_SIZE_EQUAL(actual_size, buffer.parsed_size);

    ASSERT_SIZE_EQUAL((size_t)4, actual_size);
    ASSERT_INT_EQUAL('o', result_buffer.data[0]);
    ASSERT_INT_EQUAL('o', result_buffer.data[1]);
    ASSERT_INT_EQUAL('o', result_buffer.data[2]);
    ASSERT_INT_EQUAL('o', result_buffer.data[3]);

    return true;
}

bool huffman_symbols_1(){
    uint8_t encoded[128];
    memset(encoded, 0xFF, sizeof(encoded));

    uint8_t symbol = 1;
    size_t len_bits = huffman_encode(&symbol, sizeof(symbol), encoded, sizeof(encoded));

    ASSERT_SIZE_EQUAL((size_t)23, len_bits);
    ASSERT_INT_EQUAL(0xFF, encoded[0]);
    ASSERT_INT_EQUAL(0xFF, encoded[1]);
    ASSERT_INT_EQUAL(0xB0, encoded[2]);

    return true;
}

bool huffman_encode_decode_j(){
    uint8_t encoded[128];
    uint8_t decoded[128];
    memset(encoded, 0xFF, sizeof(encoded));

    uint8_t symbol = 'j';
    size_t len_bits = huffman_encode(&symbol, sizeof(symbol), encoded, sizeof(encoded));

    size_t result_length;
    bool success = huffman_decode(encoded, len_bits, decoded, sizeof(decoded), &result_length);

    ASSERT_SIZE_EQUAL((size_t)7, len_bits);
    ASSERT_INT_EQUAL(0b11101000, encoded[0]);

    ASSERT_INT_EQUAL(true, success);
    ASSERT_SIZE_EQUAL((size_t)1, result_length);

    ASSERT_INT_EQUAL('j', decoded[0]);

    return true;
}

bool huffman_encode_decode_o(){
    uint8_t encoded[128];
    uint8_t decoded[128];
    memset(encoded, 0xFF, sizeof(encoded));

    uint8_t symbol = 'o';
    size_t len_bits = huffman_encode(&symbol, sizeof(symbol), encoded, sizeof(encoded));

    size_t result_length;
    bool success = huffman_decode(encoded, len_bits, decoded, sizeof(decoded), &result_length);

    ASSERT_SIZE_EQUAL((size_t)5, len_bits);
    ASSERT_INT_EQUAL(0b00111000, encoded[0]);

    ASSERT_INT_EQUAL(true, success);
    ASSERT_SIZE_EQUAL((size_t)1, result_length);

    ASSERT_INT_EQUAL('o', decoded[0]);

    return true;
}

bool huffman_encode_decode_127(){
    uint8_t encoded[128];
    uint8_t decoded[128];
    memset(encoded, 0xFF, sizeof(encoded));

    uint8_t symbol = 127;
    size_t len_bits = huffman_encode(&symbol, sizeof(symbol), encoded, sizeof(encoded));

    size_t result_length;
    bool success = huffman_decode(encoded, len_bits, decoded, sizeof(decoded), &result_length);

    ASSERT_SIZE_EQUAL((size_t)28, len_bits);
    ASSERT_INT_EQUAL(0xff, encoded[0]);
    ASSERT_INT_EQUAL(0xff, encoded[1]);
    ASSERT_INT_EQUAL(0xff, encoded[2]);
    ASSERT_INT_EQUAL(0xc0, encoded[3]);

    ASSERT_INT_EQUAL(true, success);
    ASSERT_SIZE_EQUAL((size_t)1, result_length);

    ASSERT_INT_EQUAL(127, decoded[0]);

    return true;
}

bool huffman_encode_decode_128(){
    uint8_t encoded[128];
    uint8_t decoded[128];
    memset(encoded, 0xFF, sizeof(encoded));

    uint8_t symbol = 128;
    size_t len_bits = huffman_encode(&symbol, sizeof(symbol), encoded, sizeof(encoded));

    size_t result_length;
    bool success = huffman_decode(encoded, len_bits, decoded, sizeof(decoded), &result_length);

    ASSERT_SIZE_EQUAL((size_t)20, len_bits);
    ASSERT_INT_EQUAL(0xff, encoded[0]);
    ASSERT_INT_EQUAL(0xfe, encoded[1]);
    ASSERT_INT_EQUAL(0x60, encoded[2]);

    ASSERT_INT_EQUAL(true, success);
    ASSERT_SIZE_EQUAL((size_t)1, result_length);

    ASSERT_INT_EQUAL(128, decoded[0]);

    return true;
}


bool huffman_all_symbols(){
    uint8_t encoded[2048];
    uint8_t decoded[512];
    uint8_t symbols[255];
    for(uint8_t i = 0; i < sizeof(symbols); i++){
        symbols[i] = i;
    }

    size_t len_bits = huffman_encode(symbols, sizeof(symbols), encoded, sizeof(encoded));
    

    size_t result_length;
    bool status = huffman_decode(encoded, len_bits, decoded, sizeof(decoded), &result_length);

    ASSERT_INT_EQUAL(status, true);
    ASSERT_BYTES_EQUAL(symbols, sizeof(symbols), decoded, result_length);

    return true;
}

bool huffman_decode_with_eos(){
    uint8_t decoded[128];

    uint8_t symbols[] = {0b00111001, 0b11111111};

    size_t result_length;
    bool success = huffman_decode(symbols, 16, decoded, sizeof(decoded), &result_length);

    ASSERT_INT_EQUAL(true, success);
    ASSERT_SIZE_EQUAL((size_t)2, result_length);

    ASSERT_INT_EQUAL('o', decoded[0]);
    ASSERT_INT_EQUAL('o', decoded[1]);

    return true;
}

bool hpack_primitives_decode_indexed_42(){
    uint8_t bits = 0b10101010;

    ParseBuffer buffer;
    buffers_init_parse_buffer(&buffer, &bits, sizeof(bits));

    HpackHeaderFieldIndexed header;
    bool status = hpack_primitives_try_decode_indexed_header_field(&buffer, &header);

    ASSERT_INT_EQUAL(true, status);
    ASSERT_SIZE_EQUAL(sizeof(bits), buffer.total_size);
    ASSERT_SIZE_EQUAL(sizeof(bits), buffer.parsed_size);
    ASSERT_INT_EQUAL(42, header.index);

    return true;
}

bool hpack_primitives_decode_indexed_500(){
    uint8_t bits[] = {0b11111111, 0b11110101, 0b00000010};

    ParseBuffer buffer;
    buffers_init_parse_buffer(&buffer, bits, sizeof(bits));

    HpackHeaderFieldIndexed header;
    bool status = hpack_primitives_try_decode_indexed_header_field(&buffer, &header);

    ASSERT_INT_EQUAL(true, status);
    ASSERT_SIZE_EQUAL(sizeof(bits), buffer.total_size);
    ASSERT_SIZE_EQUAL(sizeof(bits), buffer.parsed_size);
    ASSERT_INT_EQUAL(500, header.index);

    return true;
}

bool hpack_primitives_decode_indexed_name(){
    uint8_t bits[] = {0b01111111, 0b10110101, 0b00000011, 0b00000101, 'v', 'a', 'l', 'u', 'e'};

    uint8_t literal_buffer[5];
    ParseBuffer buffer;
    Buffer result_buffer;
    buffers_init_parse_buffer(&buffer, bits, sizeof(bits));
    buffers_init_buffer(&result_buffer, literal_buffer, sizeof(literal_buffer));

    HpackHeaderLiteralFieldIndexedName header;
    bool status = hpack_primitives_try_decode_literal_field_indexed_name(&buffer, &header, &result_buffer);

    ASSERT_INT_EQUAL(true, status);

    ASSERT_SIZE_EQUAL(sizeof(bits), buffer.total_size);
    ASSERT_SIZE_EQUAL(sizeof(bits), buffer.parsed_size);
    ASSERT_SIZE_EQUAL(sizeof(literal_buffer), result_buffer.total_size);
    ASSERT_SIZE_EQUAL(header.value_length, result_buffer.used_size);

    ASSERT_INT_EQUAL(header.index_type, IndexTypeIncremental);
    ASSERT_INT_EQUAL(500, header.index);
    ASSERT_SIZE_EQUAL((size_t)5, header.value_length);
    ASSERT_BYTES_EQUAL("value", 5, header.value, header.value_length);

    return true;
}

bool hpack_primitives_decode_indexed_name_index_73(){
    uint8_t bits[] = {
        0x7F, 0x0A, 0xB5, 0x35, 0x23, 0x98, 0xAC, 0x0F, 0xB9, 0xA5, 0xFA, 0x35, 0x23, 0x98, 0xAC,
        0x78, 0x2C, 0x75, 0xFD, 0x1A, 0x91, 0xCC, 0x56, 0x2B, 0xAA, 0x6F, 0xA3, 0x52, 0x39, 0x8A,
        0xC2, 0x3B, 0xCD, 0xFE, 0xFC, 0xD3, 0x47, 0xD1, 0xA9, 0x1C, 0xC5, 0x63, 0xE7, 0xEF, 0xB4,
        0x00, 0x5D, 0xEF, 0xAF, 0x96, 0x3E, 0x7E, 0xFB, 0x40, 0x05, 0xDB
    };

    uint8_t literal_buffer[128];
    ParseBuffer buffer;
    Buffer result_buffer;
    buffers_init_parse_buffer(&buffer, bits, sizeof(bits));
    buffers_init_buffer(&result_buffer, literal_buffer, sizeof(literal_buffer));

    HpackHeaderLiteralFieldIndexedName header;
    bool status = hpack_primitives_try_decode_literal_field_indexed_name(&buffer, &header, &result_buffer);

    ASSERT_INT_EQUAL(true, status);
    ASSERT_INT_EQUAL(73, header.index);
    char *expected = "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5";
    ASSERT_BYTES_EQUAL(expected, strlen(expected), header.value, header.value_length);

    return true;
}

bool hpack_primitives_decode_new_name(){
    uint8_t bits[] = {0b00010000, 0b00000100, 'n', 'a', 'm', 'e', 0b00000101, 'v', 'a', 'l', 'u', 'e'};

    uint8_t literal_buffer[9];
    ParseBuffer buffer;
    Buffer result_buffer;
    buffers_init_parse_buffer(&buffer, bits, sizeof(bits));
    buffers_init_buffer(&result_buffer, literal_buffer, sizeof(literal_buffer));

    HpackHeaderLiteralFieldNewName header;
    bool status = hpack_primitives_try_decode_literal_field_new_name(&buffer, &header, &result_buffer);

    ASSERT_INT_EQUAL(true, status);

    ASSERT_SIZE_EQUAL(sizeof(bits), buffer.total_size);
    ASSERT_SIZE_EQUAL(sizeof(bits), buffer.parsed_size);
    ASSERT_SIZE_EQUAL(sizeof(literal_buffer), result_buffer.total_size);
    ASSERT_SIZE_EQUAL(header.value_length + header.name_length, result_buffer.used_size);

    ASSERT_INT_EQUAL(header.index_type, IndexTypeNever);
    ASSERT_SIZE_EQUAL((size_t)4, header.name_length);
    ASSERT_BYTES_EQUAL("name", 4, header.name, header.name_length);
    ASSERT_SIZE_EQUAL((size_t)5, header.value_length);
    ASSERT_BYTES_EQUAL("value", 5, header.value, header.value_length);
    ASSERT_BYTES_EQUAL("namevalue", 9, literal_buffer, 9);

    return true;
}

static void print_header(HttpHeaderField *header){
    for(size_t i = 0; i < header->name_length; i++){
        printf("%c", header->name[i]);
    }
    printf(": ");
    for(size_t i = 0; i < header->value_length; i++){
        printf("%c", header->value[i]);
    }
    printf("\n");
}

static void print_headers(HttpHeaderField *headers, size_t count){
    for(size_t i = 0; i < count; i++){
        print_header(&headers[i]);
    }
}

bool add_entry(){
    uint8_t request1[] = {0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d};
    uint8_t request2[] = {0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65};
    uint8_t request3[] = {0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65};

    uint8_t *requests[] = {&request1, &request2, &request3};
    size_t len[] = {sizeof(request1), sizeof(request2), sizeof(request3)};
        HpackDecoder *decoder = hpack_decoder_new(4096);

    for(size_t i = 0; i < 3; i++){
        printf("===Request %zu===\n", i + 1);
        uint8_t data[1024];
        Buffer buffer;
        ParseBuffer parse_buffer;
        buffers_init_parse_buffer(&parse_buffer, requests[i], len[i]);
        buffers_init_buffer(&buffer, data, sizeof(data));

        HttpHeaderField headers[32];
        size_t header_count;

        HpackStatus status = hpack_decode_headers(decoder, &parse_buffer, headers, 32, &header_count, &buffer);
        if(status == HpackStatusOk){
            print_headers(headers, header_count);
        }
        else{
            printf("Status %d\n", status);
        }
    }

    return true;
}

bool add_entry_huffman(){
    uint8_t request1[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    uint8_t request2[] = {0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    uint8_t request3[] = {0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf};

    uint8_t *requests[] = {&request1, &request2, &request3};
    size_t len[] = {sizeof(request1), sizeof(request2), sizeof(request3)};
    HpackDecoder *decoder = hpack_decoder_new(4096);

    for(size_t i = 0; i < 3; i++){
        printf("===Request %zu===\n", i + 1);
        uint8_t data[1024];
        Buffer buffer;
        ParseBuffer parse_buffer;
        buffers_init_parse_buffer(&parse_buffer, requests[i], len[i]);
        buffers_init_buffer(&buffer, data, sizeof(data));

        HttpHeaderField headers[32];
        size_t header_count;

        HpackStatus status = hpack_decode_headers(decoder, &parse_buffer, headers, 32, &header_count, &buffer);
        if(status == HpackStatusOk){
            print_headers(headers, header_count);
        }
        else{
            printf("Status %d\n", status);
        }
    }

    return true;
}

bool add_entry_client(){
    uint8_t request1[] = {
          0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70,
          0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x61, 0x1d,
          0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20,
          0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33,
          0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32,
          0x31, 0x20, 0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68,
          0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77,
          0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
          0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
        };

    uint8_t request2[] = {
         0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf
    };

    uint8_t request3[] = {
          0x88, 0xc1, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c,
          0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20,
          0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a,
          0x31, 0x33, 0x3a, 0x32, 0x32, 0x20, 0x47, 0x4d,
          0x54, 0xc0, 0x5a, 0x04, 0x67, 0x7a, 0x69, 0x70,
          0x77, 0x38, 0x66, 0x6f, 0x6f, 0x3d, 0x41, 0x53,
          0x44, 0x4a, 0x4b, 0x48, 0x51, 0x4b, 0x42, 0x5a,
          0x58, 0x4f, 0x51, 0x57, 0x45, 0x4f, 0x50, 0x49,
          0x55, 0x41, 0x58, 0x51, 0x57, 0x45, 0x4f, 0x49,
          0x55, 0x3b, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61,
          0x67, 0x65, 0x3d, 0x33, 0x36, 0x30, 0x30, 0x3b,
          0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
          0x3d, 0x31
    };

    uint8_t *requests[] = {&request1, &request2, &request3};
    size_t len[] = {sizeof(request1), sizeof(request2), sizeof(request3)};
    HpackDecoder *decoder = hpack_decoder_new(4096);

    for(size_t i = 0; i < 3; i++){
        printf("===Request %zu===\n", i + 1);
        uint8_t data[1024];
        Buffer buffer;
        ParseBuffer parse_buffer;
        buffers_init_parse_buffer(&parse_buffer, requests[i], len[i]);
        buffers_init_buffer(&buffer, data, sizeof(data));

        HttpHeaderField headers[32];
        size_t header_count;

        HpackStatus status = hpack_decode_headers(decoder, &parse_buffer, headers, 32, &header_count, &buffer);
        if(status == HpackStatusOk){
            print_headers(headers, header_count);
        }
        else{
            printf("Status %d\n", status);
        }
    }

    return true;
}

bool add_entry_client_huffman(){
    uint8_t request1[] = {
      0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3,
      0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe,
      0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05,
      0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6,
      0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad,
      0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8,
      0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3
    };;

    uint8_t request2[] = {
      0x48, 0x83, 0x64, 0x0e, 0xff, 0xc1, 0xc0, 0xbf
    };

    uint8_t request3[] = {
      0x88, 0xc1, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94,
      0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95,
      0x04, 0x0b, 0x81, 0x66, 0xe0, 0x84, 0xa6, 0x2d,
      0x1b, 0xff, 0xc0, 0x5a, 0x83, 0x9b, 0xd9, 0xab,
      0x77, 0xad, 0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2,
      0xe6, 0xc7, 0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b,
      0x39, 0x60, 0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36,
      0x72, 0xc1, 0xab, 0x27, 0x0f, 0xb5, 0x29, 0x1f,
      0x95, 0x87, 0x31, 0x60, 0x65, 0xc0, 0x03, 0xed,
      0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07
    };

    uint8_t *requests[] = {&request1, &request2, &request3};
    size_t len[] = {sizeof(request1), sizeof(request2), sizeof(request3)};
    HpackDecoder *decoder = hpack_decoder_new(4096);

    for(size_t i = 0; i < 3; i++){
        printf("===Request %zu===\n", i + 1);
        uint8_t data[1024];
        Buffer buffer;
        ParseBuffer parse_buffer;
        buffers_init_parse_buffer(&parse_buffer, requests[i], len[i]);
        buffers_init_buffer(&buffer, data, sizeof(data));

        HttpHeaderField headers[32];
        size_t header_count;

        HpackStatus status = hpack_decode_headers(decoder, &parse_buffer, headers, 32, &header_count, &buffer);
        if(status == HpackStatusOk){
            print_headers(headers, header_count);
        }
        else{
            printf("Status %d\n", status);
        }
    }

    hpack_decoder_free(decoder);
    return true;
}

bool encode_decode_indexed_header(){
    uint8_t encoded[128];
    uint8_t decoded[128];
    Buffer encode_buffer;
    buffers_init_buffer(&encode_buffer, encoded, sizeof(encoded));

    HpackHeaderFieldIndexed expected = {
        .index = 6969
    };

    size_t encoded_size = hpack_primitives_encode_indexed_header_field(&expected, &encode_buffer);

    ParseBuffer parse_buffer;
    buffers_init_parse_buffer(&parse_buffer, encoded, encoded_size);
    HpackHeaderFieldIndexed actual;
    bool status = hpack_primitives_try_decode_indexed_header_field(&parse_buffer, &actual);

    ASSERT_INT_EQUAL(true, status);

    ASSERT_SIZE_EQUAL(sizeof(encoded), encode_buffer.total_size);
    ASSERT_SIZE_EQUAL(encode_buffer.used_size, encoded_size);

    ASSERT_SIZE_EQUAL(encoded_size, parse_buffer.total_size);
    ASSERT_SIZE_EQUAL(encoded_size, parse_buffer.parsed_size);

    ASSERT_INT_EQUAL(expected.index, actual.index);

    return true;
}

bool encode_decode_indexed_name_header(){
    uint8_t encoded[128];
    uint8_t decoded[128];
    uint8_t buffer[128];
    Buffer encode_buffer;
    buffers_init_buffer(&encode_buffer, encoded, sizeof(encoded));

    HpackHeaderLiteralFieldIndexedName expected = {
        .index = 3,
        .index_type = IndexTypeIncremental,
        .value = "Hello World!",
    };
    expected.value_length = strlen(expected.value);

    size_t encoded_size = hpack_primitives_encode_literal_field_indexed_name(&expected, &encode_buffer);

    ParseBuffer parse_buffer;
    Buffer field_buffer;
    buffers_init_parse_buffer(&parse_buffer, encoded, encoded_size);
    buffers_init_buffer(&field_buffer, buffer, sizeof(buffer));
    HpackHeaderLiteralFieldIndexedName actual;
    bool status = hpack_primitives_try_decode_literal_field_indexed_name(&parse_buffer, &actual, &field_buffer);

    ASSERT_INT_EQUAL(true, status);

    ASSERT_SIZE_EQUAL(sizeof(encoded), encode_buffer.total_size);
    ASSERT_SIZE_EQUAL(encode_buffer.used_size, encoded_size);

    ASSERT_SIZE_EQUAL(encoded_size, parse_buffer.total_size);
    ASSERT_SIZE_EQUAL(encoded_size, parse_buffer.parsed_size);
    ASSERT_SIZE_EQUAL(strlen(expected.value), field_buffer.used_size);

    ASSERT_INT_EQUAL(expected.index, actual.index);
    ASSERT_INT_EQUAL(expected.index_type, actual.index_type);
    ASSERT_BYTES_EQUAL(expected.value, expected.value_length, actual.value, actual.value_length);

    return true;
}

bool encode_decode_new_name_header(){
    uint8_t encoded[128];
    uint8_t decoded[128];
    uint8_t buffer[128];
    Buffer encode_buffer;
    buffers_init_buffer(&encode_buffer, encoded, sizeof(encoded));

    HpackHeaderLiteralFieldNewName expected = {
        .index_type = IndexTypeWithout,

        .name = "This is the name of a field. This is also part of the name",
        .value = "Hello World!"
    };
    expected.name_length = strlen(expected.name);
    expected.value_length = strlen(expected.value);

    size_t encoded_size = hpack_primitives_encode_literal_field_new_name(&expected, &encode_buffer);

    ParseBuffer parse_buffer;
    Buffer field_buffer;
    buffers_init_parse_buffer(&parse_buffer, encoded, encoded_size);
    buffers_init_buffer(&field_buffer, buffer, sizeof(buffer));
    HpackHeaderLiteralFieldNewName actual;
    bool status = hpack_primitives_try_decode_literal_field_new_name(&parse_buffer, &actual, &field_buffer);

    ASSERT_INT_EQUAL(true, status);

    ASSERT_SIZE_EQUAL(sizeof(encoded), encode_buffer.total_size);
    ASSERT_SIZE_EQUAL(encode_buffer.used_size, encoded_size);

    ASSERT_SIZE_EQUAL(encoded_size, parse_buffer.total_size);
    ASSERT_SIZE_EQUAL(encoded_size, parse_buffer.parsed_size);
    ASSERT_SIZE_EQUAL(strlen(expected.name) + strlen(expected.value), field_buffer.used_size);

    ASSERT_INT_EQUAL(expected.index_type, actual.index_type);
    ASSERT_BYTES_EQUAL(expected.name, expected.name_length, actual.name, actual.name_length);
    ASSERT_BYTES_EQUAL(expected.value, expected.value_length, actual.value, actual.value_length);

    return true;
}

bool huffman(){
    uint8_t bytes[] = {0x89, 0x62, 0x51, 0xF7, 0x31, 0x0F, 0x52, 0xE6, 0x21, 0xFF};
    char result[128];

    ParseBuffer buffer;
    Buffer result_buffer;
    buffers_init_parse_buffer(&buffer, bytes, sizeof(bytes));
    buffers_init_buffer(&result_buffer, result, sizeof(result));

    size_t actual_size;
    bool success = hpack_primitives_try_decode_string(&buffer, &result_buffer, &actual_size);

    printf("\nDecoded %d\n", success);
    for(size_t i = 0; i < actual_size; i++){
        printf("%c", result[i]);
    }
    printf("\n");
    return true;
}


Test tests[] = {
    TEST(encode_decode_int_1_prefix_1),
    TEST(encode_decode_int_2_prefix_1),
    TEST(encode_decode_int_129_prefix_1),
    TEST(encode_decode_int_0_to_million_all_prefixes),
    TEST(encode_decode_uint_max_all_prefixes),
    TEST(encode_decode_str_len_3),
    TEST(encode_decode_str_len_0_to_64),
    TEST(decode_huffman_str),
    TEST(huffman_symbols_1),
    TEST(huffman_encode_decode_j),
    TEST(huffman_encode_decode_o),
    TEST(huffman_encode_decode_127),
    TEST(huffman_encode_decode_128),
    TEST(huffman_all_symbols),
    TEST(huffman_decode_with_eos),
    TEST(hpack_primitives_decode_indexed_42),
    TEST(hpack_primitives_decode_indexed_500),
    TEST(hpack_primitives_decode_indexed_name),
    TEST(hpack_primitives_decode_new_name),
    TEST(add_entry_client),
    TEST(add_entry_client_huffman),
    TEST(encode_decode_indexed_header),
    TEST(encode_decode_indexed_name_header),
    TEST(encode_decode_new_name_header),
//        TEST(huffman),
//        TEST(hpack_primitives_decode_indexed_name_index_73)
};
const size_t test_count = sizeof(tests) / sizeof(Test);
