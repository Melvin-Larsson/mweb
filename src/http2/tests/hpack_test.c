#include "test_harness.h"
#include "http2/huffman.h"
#include "http2/hpack_primitives.h"
#include <assert.h>
#include <limits.h>
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

    size_t len = hpack_primitives_encode_int(buff, sizeof(buff), prefix, value); 

    unsigned int decoded;
    bool status = hpack_primitives_try_decode_int(buff, sizeof(buff), prefix, &decoded); 

    ASSERT_INT_EQUAL(status, true);
    ASSERT_INT_EQUAL(value, decoded);

    return true;
}


bool _test_str_encode_no_huffman(size_t count){
    assert(count <= 64);
    char str[64];
    char encoded[128];
    char decoded[64];

    for(size_t i = 0; i < count; i++){
        str[i] = 'A' + i;
    }

    size_t encoded_size = hpack_primitives_encode_string(str, count, encoded, sizeof(encoded));

    size_t decoded_size;
    hpack_primitives_try_decode_string(encoded, sizeof(encoded), decoded, sizeof(decoded), &decoded_size);

    ASSERT_INT_EQUAL(count, decoded_size);
    ASSERT_BYTES_EQUAL(str, count, decoded, decoded_size);

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
    char bytes[] = {0b10000011, 0b00111001, 0b11001110, 0b01111111};
    char result[128];

    size_t actual_size;
    bool success = hpack_primitives_try_decode_string(bytes, sizeof(bytes), result, sizeof(result), &actual_size);

    ASSERT_INT_EQUAL(true, success);
    ASSERT_SIZE_EQUAL((size_t)4, actual_size);
    ASSERT_INT_EQUAL('o', result[0]);
    ASSERT_INT_EQUAL('o', result[1]);
    ASSERT_INT_EQUAL('o', result[2]);
    ASSERT_INT_EQUAL('o', result[3]);

    return true;
}

bool huffman_symbols_1(){
    uint8_t encoded[128];
    memset(encoded, 0xFF, sizeof(encoded));

    uint8_t symbol = 1;
    size_t len_bits = huffman_encode((char *)&symbol, sizeof(symbol), (char *)encoded, sizeof(encoded));

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
    size_t len_bits = huffman_encode((char *)&symbol, sizeof(symbol), (char *)encoded, sizeof(encoded));

    size_t result_length;
    bool success = huffman_decode((char *)encoded, len_bits, (char *)decoded, sizeof(decoded), &result_length);

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
    size_t len_bits = huffman_encode((char *)&symbol, sizeof(symbol), (char *)encoded, sizeof(encoded));

    size_t result_length;
    bool success = huffman_decode((char *)encoded, len_bits, (char *)decoded, sizeof(decoded), &result_length);

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
    size_t len_bits = huffman_encode((char *)&symbol, sizeof(symbol), (char *)encoded, sizeof(encoded));

    size_t result_length;
    bool success = huffman_decode((char *)encoded, len_bits, (char *)decoded, sizeof(decoded), &result_length);

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
    size_t len_bits = huffman_encode((char *)&symbol, sizeof(symbol), (char *)encoded, sizeof(encoded));

    size_t result_length;
    bool success = huffman_decode((char *)encoded, len_bits, (char *)decoded, sizeof(decoded), &result_length);

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
    char encoded[2048];
    char decoded[512];
    char symbols[255];
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
    bool success = huffman_decode((char *)symbols, 16, (char *)decoded, sizeof(decoded), &result_length);

    ASSERT_INT_EQUAL(true, success);
    ASSERT_SIZE_EQUAL((size_t)2, result_length);

    ASSERT_INT_EQUAL('o', decoded[0]);
    ASSERT_INT_EQUAL('o', decoded[1]);

    return true;
}


Test tests[] = {
//     TEST(encode_decode_int_1_prefix_1),
//     TEST(encode_decode_int_2_prefix_1),
//     TEST(encode_decode_int_129_prefix_1),
//     TEST(encode_decode_int_0_to_million_all_prefixes),
//     TEST(encode_decode_uint_max_all_prefixes),
//     TEST(encode_decode_str_len_3),
//     TEST(encode_decode_str_len_0_to_64),
    TEST(decode_huffman_str),
//     TEST(huffman_symbols_1),
//     TEST(huffman_encode_decode_j),
//     TEST(huffman_encode_decode_o),
//     TEST(huffman_encode_decode_127),
//     TEST(huffman_encode_decode_128),
//     TEST(huffman_all_symbols),
//     TEST(huffman_decode_with_eos)
};
const size_t test_count = sizeof(tests) / sizeof(Test);
