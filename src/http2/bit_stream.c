#include "bit_stream.h"

#define BITMASK(n) ((1U << (n)) - 1U)
#define min(a, b) ((a) < (b) ? (a) : (b))

void bit_stream_init_empty(uint8_t *buffer, size_t buffer_size, BitStream *bit_stream){
    *bit_stream = (BitStream){
        .buffer = buffer,
        .buffer_size = buffer_size,
        .input_offset = 0,
        .output_offset = 0
    };
}

void bit_stream_init_with_bits(uint8_t *buffer, size_t buffer_size, size_t used_bits, BitStream *bit_stream){
    *bit_stream = (BitStream){
        .buffer = buffer,
        .buffer_size = buffer_size,
        .input_offset = used_bits,
        .output_offset = 0
    };
}

size_t bit_stream_push(BitStream *bit_stream, uint8_t *buffer, size_t bit_count){
    size_t byte_offset = bit_stream->input_offset / 8;
    size_t bit_offset = bit_stream->input_offset % 8;

    size_t pushed_bits = 0;
    for(size_t i = 0; i < bit_count; i += 8){
        if(byte_offset == bit_stream->buffer_size){
            break;
        }
        bit_stream->buffer[byte_offset] = (bit_stream->buffer[byte_offset] & ~BITMASK(8 - bit_offset)) | *buffer >> bit_offset;
        pushed_bits += 8 - bit_offset;
        if(byte_offset + 1 == bit_stream->buffer_size){
            break;
        }
        bit_stream->buffer[byte_offset + 1] = *buffer << (8 - bit_offset);
        pushed_bits += bit_offset;

        buffer++;
        byte_offset++;
    }

    pushed_bits = min(pushed_bits, bit_count);
    bit_stream->input_offset += pushed_bits;
    return pushed_bits;
}

size_t bit_stream_peak(BitStream *bit_stream, uint8_t *buffer, size_t bit_count){
    size_t s = bit_stream_pull(bit_stream, buffer, bit_count);
    bit_stream->output_offset -= s;
    return s;
}

size_t bit_stream_pull(BitStream *bit_stream, uint8_t *buffer, size_t bit_count){
    size_t byte_offset = bit_stream->output_offset / 8;
    size_t bit_offset = bit_stream->output_offset % 8;

    size_t pulled_bits = 0;
    for(size_t i = 0; i < bit_count; i += 8){
        char old_value = *buffer;
        if(bit_stream->output_offset + pulled_bits >= bit_stream->input_offset){
            break;
        }
        *buffer = (bit_stream->buffer[byte_offset] & BITMASK(8 - bit_offset)) << bit_offset;
        pulled_bits += 8 - bit_offset;

        if(bit_stream->output_offset + pulled_bits >= bit_stream->input_offset){
//             if(bit_count - i < 8){
//                 *buffer = (*buffer >> (8 - (bit_count - i))) | (old_value & ~BITMASK(bit_count - i));
//             }
            break;
        }
        *buffer |= bit_stream->buffer[byte_offset + 1] >> (8 - bit_offset);
        pulled_bits += bit_offset;

//         if(bit_count - i < 8){
//             *buffer = (*buffer >> (8 - (bit_count - i))) | (old_value & ~BITMASK(bit_count - i));
//         }

        buffer++;
        byte_offset++;
    }

    pulled_bits = min(pulled_bits, bit_count);
    bit_stream->output_offset += pulled_bits;
    return pulled_bits;
}

size_t bit_stream_get_bits_count(BitStream *bit_stream){
    return bit_stream->input_offset - bit_stream->output_offset;
}
