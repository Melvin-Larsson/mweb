#ifndef HUFFMAN_H
#define HUFFMAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

size_t huffman_encode(uint8_t *data, size_t data_size, uint8_t *result, size_t max_result_size);
bool huffman_decode(uint8_t *data, size_t data_bit_count, uint8_t *result, size_t max_result_size, size_t *actual_result_size);

#endif 
