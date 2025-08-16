#include "huffman.h"
#include "huffman_table.h"
#include "bit_stream.h"
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>

#define BITMASK(n) ((1U << (n)) - 1U)
#define min(a, b) ((a) < (b) ? (a) : (b))

void printBits(unsigned int num, size_t len)
{
    printf("0b");
   for(int bit = 0; bit < len; bit++)
   {
      if(bit % 8 == 0){
          printf(" | ");
      }
      printf("%i", (num >> (len - bit - 1)) & 1);
   }
}


typedef struct HuffmanNode{
    HuffmanCode code;
    struct HuffmanNode *left;
    struct HuffmanNode *right;
}HuffmanNode;

typedef struct{
    HuffmanNode *nodes;
    size_t used_count;
    size_t total_count;
}HuffmanNodeBuffer;

typedef struct{
    HuffmanNode *nodes;
}HuffmanTree;

typedef struct{
    bool is_leaf;
    union{
        HuffmanNode *node;
        HuffmanCode code;
    };
}LookupEntry;

static bool _huffman_tree_add(HuffmanTree *tree, int position, HuffmanCode code);
static size_t _sort_by_bit(HuffmanCode *code, size_t left, size_t right, int bit);
static HuffmanCode _remove_shortest(HuffmanCode *code, size_t *left, size_t *right);
static bool _huffman_tree_create(HuffmanTree *tree, int bit, int position, HuffmanCode *code, size_t left, size_t right);

static bool _initialize();
static bool _initialize_huffman_tree(uint8_t prefix, HuffmanNodeBuffer *buffer, HuffmanNode **result);

static bool initialized = false;
static HuffmanTree tree;
static LookupEntry lookup_table[256];

static bool _initialize(){
    size_t huffman_count = sizeof(huffman_table) / sizeof(HuffmanCode);
    HuffmanNodeBuffer buffer = {
        .nodes = calloc(huffman_count * 1.5, sizeof(HuffmanNode)),
        .total_count = huffman_count * 1.5,
        .used_count = 0,
    };
    if(buffer.nodes == NULL){
        return false;
    }

    memset(buffer.nodes, 0, buffer.total_count * sizeof(HuffmanNode));
    memset(lookup_table, 0, sizeof(lookup_table));

    for(size_t i = 0; i < huffman_count; i++){
        if(huffman_table[i].length <= 8){
            uint8_t code = huffman_table[i].code << (8 - huffman_table[i].length);

            for(size_t j = 0; j <= BITMASK(8 - huffman_table[i].length); j++){
                uint8_t index = code | j;
                lookup_table[index] = (LookupEntry){
                    .is_leaf = true,
                    .code = huffman_table[i]
                };
            }
        }
        else{
            uint8_t prefix = (huffman_table[i].code >> (huffman_table[i].length - 8)) & 0xFF; 
            if(!lookup_table[prefix].is_leaf && lookup_table[prefix].node == NULL){
                if(!_initialize_huffman_tree(prefix, &buffer, &lookup_table[prefix].node)){
                    return false;
                }
            }
        }
    }

    return true;
}


static bool _initialize_huffman_tree(uint8_t prefix, HuffmanNodeBuffer *buffer, HuffmanNode **result){
    size_t long_huffman_count = 0;
    HuffmanNode *root = &buffer->nodes[buffer->used_count++];
    *result = root;
    size_t huffman_count = sizeof(huffman_table) / sizeof(HuffmanCode);
    for(size_t i = 0; i < huffman_count; i++){
        if(huffman_table[i].length > 8 && ((huffman_table[i].code >> (huffman_table[i].length - 8)) & 0xFF) == prefix){
            HuffmanNode *node = root;
            for(int bit_pos = huffman_table[i].length - 9; bit_pos >= 0; bit_pos--){
                if(huffman_table[i].code & (1 << bit_pos)){
                    if(node->right == NULL){
                        assert(buffer->used_count < buffer->total_count);
                        node->right = &buffer->nodes[buffer->used_count++];
                    }
                    node = node->right;
                }else{
                    if(node->left == NULL){
                        assert(buffer->used_count < buffer->total_count);
                        node->left = &buffer->nodes[buffer->used_count++];
                    }
                    node = node->left;
                }
            }
            node->code = huffman_table[i];
        }
    }

    return true;
}

size_t huffman_encode(uint8_t *data, size_t data_size, uint8_t *result, size_t max_result_size){
    BitStream bs;
    bit_stream_init_empty(result, max_result_size, &bs);
    size_t tot = 0;
    for(size_t i = 0; i < data_size; i++){
        HuffmanCode code = huffman_table[(uint8_t)data[i]];
        uint32_t val = code.code << (32 - code.length);
        uint8_t bytes[] = {(val & 0xFF000000) >> 24, (val & 0xFF0000) >> 16, (val & 0xFF00) >> 8, val & 0xFF};

        bit_stream_push(&bs, bytes, code.length);
    }

    return bit_stream_get_bits_count(&bs);
}


HuffmanCode _decode_from_node(HuffmanNode *node , uint32_t code){
    uint32_t reverse = __bswap_32(code);
    for(size_t i = 8; i < sizeof(code) * 8; i++){
        if(node == NULL){
            return (HuffmanCode){0};
        }
        if(node->code.length != 0 && node->code.code == (reverse >> (sizeof(reverse) * 8 - node->code.length))){
            return node->code;
        }
        if(reverse & (1 << (sizeof(reverse) * 8 - i - 1))){
            node = node->right;
        }
        else{
            node = node->left;
        }
    }
    return (HuffmanCode){0};
}
HuffmanCode _decode(uint32_t code){
    assert(initialized);
    uint8_t index = code & 0xFF;
    LookupEntry entry = lookup_table[index];
    if(entry.is_leaf){
        return entry.code;
    }
    return _decode_from_node(entry.node, code);
}

bool huffman_decode(uint8_t *data, size_t data_bit_count, uint8_t *result, size_t max_result_size, size_t *actual_result_size){
    if(!initialized){
        initialized = _initialize();
        if(!initialized){
            return false;
        }
    }
    *actual_result_size = 0;
    BitStream bs;
    bit_stream_init_with_bits((uint8_t *)data, (data_bit_count + 7)/ 8, data_bit_count, &bs);
    while(bit_stream_get_bits_count(&bs) > 0 && max_result_size > 0){
        uint32_t code = 0;
        size_t pulled = bit_stream_peak(&bs, (uint8_t *)&code, 32);
        HuffmanCode hc = _decode(code);
        if(hc.length == 0 || hc.length > pulled){
            return pulled < 8 && code >> (8 - pulled) == BITMASK(pulled);
        }
        bit_stream_pull(&bs, (uint8_t *)&code, hc.length);
        *result = hc.symbol;
        result++;
        max_result_size--;
        (*actual_result_size)++;
    }

    return true;
}

