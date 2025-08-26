#ifndef HTTP_MESSAGE_H
#define HTTP_MESSAGE_H

#include "buffers.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdalign.h>

typedef enum{
    GET,
    POST,
    PUT,
    DELETE
}Method;

typedef enum{
    HttpStatus200,
    HttpStatus400,
    HttpStatus404,
}HttpStatus;

typedef struct{
    const char *name;
    const char *value;
    size_t name_length;
    size_t value_length;
}HttpHeaderField;

typedef struct{
    Method method;

    const char *path;
    size_t path_length;

    HttpHeaderField *headers;    
    size_t header_count;

    const uint8_t *body;
    size_t body_size;
}HttpRequest;

typedef struct{
    HttpStatus status;

    HttpHeaderField *headers;    
    size_t header_count;

    uint8_t *body;
    size_t body_size;
}HttpResponse;

static inline void http_header_field_print(HttpHeaderField *field){
    for(size_t i = 0; i < field->name_length; i++){
        printf("%c", field->name[i]);
    }
    printf(": ");
    for(size_t i = 0; i < field->value_length; i++){
        printf("%c", field->value[i]);
    }
    printf("\n");
}

static inline void http_header_fields_print(HttpHeaderField *fields, size_t count){
    for(size_t i = 0; i < count; i++){
        http_header_field_print(&fields[i]);
    }
}

static inline HttpResponse http_response_empty(HttpStatus status){
    return (HttpResponse){
        .status = status,
        .headers = NULL,
        .header_count = 0,
        .body = NULL,
        .body_size = 0
    };
}

static inline HttpHeaderField http_header_field_from_str(char *name, char *value){
    return (HttpHeaderField){
        .name = name,
        .value = value,
        .name_length = strlen(name),
        .value_length = strlen(value)
    };
}

static inline size_t http_header_fields_get_length(HttpHeaderField *fields, size_t count){
    size_t size = 0;
    for(size_t i = 0; i < count; i++){
        HttpHeaderField *field = &fields[i];
        size += field->name_length + field->value_length;
    }   
    return size;
}

static inline size_t http_header_fields_strs_to_buffer(HttpHeaderField *fields, size_t count, Buffer *buffer){
    size_t size = 0;
    for(size_t i = 0; i < count; i++){
        HttpHeaderField *field = &fields[i];
        uint8_t *name_ptr = buffer_get_append_ptr(buffer);
        size += buffers_append(buffer, (uint8_t *)field->name, field->name_length);
        uint8_t *value_ptr = buffer_get_append_ptr(buffer);
        size += buffers_append(buffer, (uint8_t *)field->value, field->value_length);

        field->name = (char *)name_ptr;
        field->value = (char *)value_ptr;
    }

    return size;
}

static inline HttpHeaderField *http_header_fields_to_buffer(HttpHeaderField *fields, size_t count, Buffer *buffer){
    http_header_fields_strs_to_buffer(fields, count, buffer);

    const int alignment = alignof(HttpHeaderField);
    while(buffer->used_size % alignment != 0){
        buffer->used_size++;
    }
    if(buffer->used_size >= buffer->total_size){
        buffer->used_size = buffer->total_size;
        return NULL;
    }

    HttpHeaderField *result = (HttpHeaderField *)&buffer->data[buffer->used_size];
    HttpHeaderField *curr = result;
    for(size_t i = 0; i < count; i++){
        size_t size_left = buffer_size_left(buffer);
        if(size_left >= sizeof(HttpHeaderField)){
            memcpy(curr, &fields[i], sizeof(HttpHeaderField));
            buffer->used_size += sizeof(HttpHeaderField);
            curr++;
        }
        else{
            buffer->used_size = buffer->total_size;
            return result;
        }
    }

    return result;
}

static inline HttpHeaderField http_status_header_field(HttpStatus status){
    char *value;
    switch(status){
        case HttpStatus200:
            value = "200";
            break;
        case HttpStatus400:
            value = "400";
            break;
        case HttpStatus404:
            value = "404";
            break;
        default:
            assert(0 && "Invalid status");
    }

    return http_header_field_from_str(":status", value);
}

#endif
