#ifndef BUFFERS_H
#define BUFFERS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct{
    uint8_t *data;
    size_t parsed_size;
    size_t total_size;
}ParseBuffer;

typedef struct{
    uint8_t *data;
    size_t used_size;
    size_t total_size;
}Buffer;

static inline void buffers_init_parse_buffer(ParseBuffer *buffer, uint8_t *data, size_t size){
    *buffer = (ParseBuffer){
        .parsed_size = 0,
        .data = data,
        .total_size = size
    };
}

static size_t buffers_append_parse_buffer(ParseBuffer *buffer, uint8_t *data, size_t size){
    size_t size_left = buffer->total_size - buffer->parsed_size;
    size_t copy_size = size_left > size ? size : size_left;
    memcpy(&buffer->data[buffer->parsed_size], data, copy_size);
    buffer->parsed_size += copy_size;

    return copy_size;
}

static inline void buffers_init_buffer(Buffer *buffer, uint8_t *data, size_t size){
    *buffer = (Buffer){
        .used_size = 0,
        .data = data,
        .total_size = size
    };
}

static size_t buffers_append(Buffer *buffer, uint8_t *data, size_t size){
    size_t size_left = buffer->total_size - buffer->used_size;
    size_t copy_size = size_left > size ? size : size_left;
    memcpy(&buffer->data[buffer->used_size], data, copy_size);
    buffer->used_size += copy_size;
    return copy_size;
}

static size_t buffer_size_left(Buffer *buffer){
    return buffer->total_size - buffer->used_size;
}

static bool buffer_size_is_full(Buffer *buffer){
    return buffer->used_size >= buffer->total_size;
}

static uint8_t *buffer_get_append_ptr(Buffer *buffer){
    return &buffer->data[buffer->used_size];
}

static size_t buffer_snprintf(Buffer *buffer, const char *fmt, ...){
    va_list args;
    va_start(args, fmt);

    size_t size_left = buffer_size_left(buffer);
    char *ptr = (char *)buffer_get_append_ptr(buffer);
    size_t used_size = vsnprintf(ptr, size_left, fmt, args);

    buffer->used_size += used_size;

    va_end(args);
    return used_size;
}


#endif
