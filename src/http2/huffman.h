#ifndef HUFFMAN_H
#define HUFFMAN_H

#include <stdbool.h>
#include <stddef.h>

size_t huffman_encode(char *data, size_t data_size, char *result, size_t max_result_size);
bool huffman_decode(char *data, size_t data_bit_count, char *result, size_t max_result_size, size_t *actual_result_size);

#endif 
