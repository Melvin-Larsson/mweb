#include "stringbuilder.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_GROWTH_RATE 1.5

struct StringBuilder{
    char *str;
    char *end_ptr;
    size_t buffer_size;

    float growth_rate;
};

StringBuilder *string_builder_new(size_t size_hint){
    assert(size_hint > 0);

    StringBuilder *builder = malloc(sizeof(StringBuilder));
    if(builder == NULL){
        return NULL;
    }

    *builder = (StringBuilder){
        .buffer_size = size_hint,
        .str = malloc(size_hint),
        .growth_rate = DEFAULT_GROWTH_RATE
    };
    builder->end_ptr = builder->str;

    if(!builder->str){
        free(builder);
        return NULL;
    }

    return builder;
}

void string_builder_free(StringBuilder *string_builder){
    if(string_builder == NULL){
        return;
    }
    
    free(string_builder->str);
    string_builder->str = NULL;
    string_builder->end_ptr = NULL;
    free(string_builder);
}

void string_builder_set_growth_rate(StringBuilder *string_builder, float growth_rate){
    assert(string_builder != NULL);
    assert(growth_rate > 1);

    string_builder->growth_rate = growth_rate;
}

bool string_builder_append(StringBuilder *string_builder, const char *string){
    return string_builder_append_len(string_builder, string, SIZE_MAX);
}

bool string_builder_append_len(StringBuilder *string_builder, const char *string, size_t len){
    assert(string_builder != NULL);
    if(string == NULL){
        return true;
    }

    size_t buffer_used_size = string_builder->end_ptr - string_builder->str;
    size_t buffer_size_left = string_builder->buffer_size - buffer_used_size;

    size_t appended = 0;
    while(len-- > 0 && *string && appended < buffer_size_left){
        *string_builder->end_ptr++ = *string++;
        appended++;
    }

    if(appended == buffer_size_left){
        size_t new_size = string_builder->buffer_size * string_builder->growth_rate;
        char *new_buff = realloc(string_builder->str, new_size);
        if(new_buff == NULL){
            string_builder->end_ptr -= appended;
            return false;
        }

        string_builder->str = new_buff;
        string_builder->end_ptr = string_builder->str + buffer_used_size + appended;
        string_builder->buffer_size = new_size;

        return string_builder_append_len(string_builder, string, len);
    }

    *string_builder->end_ptr = '\0';

    return true;
}

const char *string_builder_get_string(StringBuilder *string_builder){
    assert(string_builder != NULL);

    return string_builder->str;
}

char *string_builder_to_string(StringBuilder *string_builder){
    size_t buffer_used_size = string_builder->end_ptr - string_builder->str;
    char *result = malloc(buffer_used_size + 1);
    memcpy(result, string_builder->str, buffer_used_size);
    result[buffer_used_size] = '\0';
    return result;
}

char *string_builder_to_string_and_free(StringBuilder *string_builder){
    assert(string_builder != NULL);
    char *result = string_builder->str;

    string_builder->str = NULL;
    string_builder->end_ptr = NULL;
    free(string_builder);

    return result;
}
