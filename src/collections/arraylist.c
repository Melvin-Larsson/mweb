#include "collections/arraylist.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_ENTRY_COUNT 8
#define SCALING_FACTOR 1.5

struct ArrayList{
    uint8_t *data;
    size_t used_entry_count;
    size_t buffer_entry_count;
    size_t entry_size;
};

struct ArrayListIterator{
    ArrayList *array_list;
    size_t index;
};

ArrayList *array_list_new(size_t entry_size){
    ArrayList *list = malloc(sizeof(ArrayList));
    uint8_t *data = calloc(DEFAULT_ENTRY_COUNT, entry_size);

    if(list == NULL || data == NULL){
        free(list);
        free(data);
        return NULL;
    }

    *list = (ArrayList){
        .data = data,
        .used_entry_count = 0,
        .buffer_entry_count = DEFAULT_ENTRY_COUNT,
        .entry_size = entry_size
    };

    return list;
}

void array_list_free(ArrayList *list){
    if(list == NULL){
        return;
    }
    free(list->data);
    list->data = NULL;

    free(list);
}

bool array_list_add(ArrayList *list, void *data){
    if(list->used_entry_count == list->buffer_entry_count){
        size_t new_count = list->buffer_entry_count * SCALING_FACTOR;
        assert(new_count > list->buffer_entry_count);
        uint8_t *new_buffer = calloc(new_count, list->entry_size);
        if(new_buffer == NULL){
            return false;
        }
        memcpy(new_buffer, list->data, list->buffer_entry_count * list->entry_size);
        free(list->data);
        list->data = new_buffer;
        list->buffer_entry_count = new_count;
    }

    uint8_t *new_entry = list->data + (list->used_entry_count++) * list->entry_size;
    memcpy(new_entry, data, list->entry_size);
    return true;
}

void array_list_get(ArrayList *list, size_t index, void *result){
    if(index >= list->used_entry_count){
        fprintf(stderr, "ArrayList index out of bounds: %zu >= %zu\n", index, list->used_entry_count);
        abort();
    }

    uint8_t *entry = list->data + index * list->entry_size;
    memcpy(result, entry, list->entry_size);
}

void array_list_remove(ArrayList *list, size_t index){
    if(index >= list->used_entry_count){
        fprintf(stderr, "ArrayList index out of bounds: %zu >= %zu\n", index, list->used_entry_count);
        abort();
    }

    uint8_t *entry = list->data + index * list->entry_size;
    size_t entry_count_after = list->used_entry_count - index - 1;
    memcpy(entry, entry + list->entry_size, entry_count_after * list->entry_size);
}

size_t array_list_size(ArrayList *list){
    return list->used_entry_count;
}

ArrayListIterator *array_list_create_iterator(ArrayList *list){
    ArrayListIterator *iterator = malloc(sizeof(ArrayListIterator));
    if(iterator == NULL){
        return NULL;
    }
    *iterator = (ArrayListIterator){
        .index = 0,
        .array_list = list
    };

    return iterator;
}

bool array_list_iterator_next(ArrayListIterator *iterator, void *result){
    if(iterator->index < iterator->array_list->buffer_entry_count){
        array_list_get(iterator->array_list, iterator->index++, result);
        return true;
    }
    return false;
}

void array_list_iterator_free(ArrayListIterator *iterator){
    free(iterator);
}
