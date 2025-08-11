#ifndef BIT_STREAM
#define BIT_STREAM

#include <stddef.h>
#include <stdint.h>

typedef struct{
    uint8_t *buffer;
    size_t output_offset;
    size_t input_offset;
    size_t buffer_size;
}BitStream;

void bit_stream_init_empty(uint8_t *buffer, size_t buffer_size, BitStream *bit_stream);
void bit_stream_init_with_bits(uint8_t *buffer, size_t buffer_size, size_t used_bits, BitStream *bit_stream);
size_t bit_stream_push(BitStream *bit_stream, uint8_t *buffer, size_t bit_count);
size_t bit_stream_pull(BitStream *bit_stream, uint8_t *buffer, size_t max_bit_count);
size_t bit_stream_peak(BitStream *bit_stream, uint8_t *buffer, size_t bit_count);

size_t bit_stream_get_bits_count(BitStream *bit_stream);

#endif
