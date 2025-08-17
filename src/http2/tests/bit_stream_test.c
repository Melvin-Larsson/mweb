#include "test_harness.h"
#include "bit_stream.h"
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

void _printBits(const char *msg, unsigned int num, size_t len){
    printf("%s0b", msg);
    for(int bit=0;bit<len; bit++)
    {
      printf("%i", (num >> (len - bit - 1)) & 1);
    }
    printf("\n");
}

bool push_16(){
    uint8_t buff[128];
    uint8_t input[] = {0b10010000, 0b01100001};
    BitStream bs;
    bit_stream_init_empty(buff, sizeof(buff), &bs);

    size_t pushed = bit_stream_push(&bs, input, 16);

    ASSERT_SIZE_EQUAL((size_t)16, pushed);
    ASSERT_INT_EQUAL(input[0], buff[0]);
    ASSERT_INT_EQUAL(input[1], buff[1]);

    return true;
}

bool push_7_then_1(){
    uint8_t buff[128];
    memset(buff, 0xFF, sizeof(buff));
    uint8_t input[] = {0b10010000};
    BitStream bs;
    bit_stream_init_empty(buff, sizeof(buff), &bs);

    size_t s1 = bit_stream_push(&bs, input, 7);
    size_t s2 = bit_stream_push(&bs, input, 1);

    ASSERT_SIZE_EQUAL((size_t)7, s1);
    ASSERT_SIZE_EQUAL((size_t)1, s2);
    ASSERT_INT_EQUAL(0b10010001, buff[0]);

    return true;
}

bool push_125_then_3(){
    uint8_t buff[128];
    memset(buff, 0xFF, sizeof(buff));
    uint8_t input[16];
    memset(input, 0b10101010, sizeof(input));
    BitStream bs;
    bit_stream_init_empty(buff, sizeof(buff), &bs);

    size_t s1 = bit_stream_push(&bs, input, 125);
    size_t s2 = bit_stream_push(&bs, input, 4);

    ASSERT_SIZE_EQUAL((size_t)125, s1);
    ASSERT_SIZE_EQUAL((size_t)3, s2);
    ASSERT_BYTES_EQUAL(buff, sizeof(input) - 1, input, sizeof(input) - 1);
    ASSERT_INT_EQUAL(0b10101101, buff[15]);

    return true;
}

bool push_7s(){
    uint8_t buff[128];
    uint8_t input = 0b10101010;
    uint8_t expected[] = {0b10101011, 0b01010110, 0b10101101};
    BitStream bs;
    bit_stream_init_empty(buff, sizeof(buff), &bs);

    size_t s1 = bit_stream_push(&bs, &input, 7);
    size_t s2 = bit_stream_push(&bs, &input, 7);
    size_t s3 = bit_stream_push(&bs, &input, 7);
    size_t s4 = bit_stream_push(&bs, &input, 7);

    ASSERT_SIZE_EQUAL((size_t)7, s1);
    ASSERT_SIZE_EQUAL((size_t)7, s2);
    ASSERT_SIZE_EQUAL((size_t)7, s3);
    ASSERT_SIZE_EQUAL((size_t)7, s4);

    ASSERT_BYTES_EQUAL(expected, sizeof(expected), buff, sizeof(expected));

    return true;
}

bool push_pull_8(){
    uint8_t buff[128];
    uint8_t input = 0b10101010;
    uint8_t result[] = {0xFF, 0x69};
    BitStream bs;
    bit_stream_init_empty(buff, sizeof(buff), &bs);

    size_t s1 = bit_stream_push(&bs, &input, 8);
    size_t s2 = bit_stream_pull(&bs, result, 8);

    ASSERT_SIZE_EQUAL((size_t)8, s1);
    ASSERT_SIZE_EQUAL((size_t)8, s2);
    ASSERT_INT_EQUAL(input, result[0]);
    ASSERT_INT_EQUAL(0x69, result[1]);

    return true;
}

bool push_pull_7(){
    uint8_t buff[128];
    uint8_t input = 0b11100000;
    uint8_t result[] = {0, 0x69};
    BitStream bs;
    bit_stream_init_empty(buff, sizeof(buff), &bs);

    size_t s1 = bit_stream_push(&bs, &input, 7);
    size_t s2 = bit_stream_pull(&bs, result, 7);

    ASSERT_SIZE_EQUAL((size_t)7, s1);
    ASSERT_SIZE_EQUAL((size_t)7, s2);
    ASSERT_INT_EQUAL(input >> 1, result[0]);
    ASSERT_INT_EQUAL(0x69, result[1]);

    return true;
}

bool push_pull_more_than_push(){
    uint8_t buff[128];
    uint8_t input = 0b11100000;
    uint8_t result[] = {0, 0x69};
    BitStream bs;
    bit_stream_init_empty(buff, sizeof(buff), &bs);

    size_t s1 = bit_stream_push(&bs, &input, 7);
    size_t s2 = bit_stream_pull(&bs, result, 69);

    ASSERT_SIZE_EQUAL((size_t)7, s1);
    ASSERT_SIZE_EQUAL((size_t)7, s2);
    ASSERT_INT_EQUAL(input >> 1, result[0]);
    ASSERT_INT_EQUAL(0x69, result[1]);
}

Test tests[] = {
    TEST(push_16),
    TEST(push_7_then_1),
    TEST(push_7s),
    TEST(push_pull_8),
    TEST(push_pull_7),
};
const size_t test_count = sizeof(tests) / sizeof(Test);
