#ifndef ARRAY_LIST_H
#define ARRAY_LIST_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ArrayList ArrayList;
typedef struct ArrayListIterator ArrayListIterator;

ArrayList *array_list_new(size_t entry_size);
void array_list_free(ArrayList *list);

bool array_list_add(ArrayList *list, void *data);
void array_list_get(ArrayList *list, size_t index, void *result);
void array_list_remove(ArrayList *list, size_t index);
size_t array_list_size(ArrayList *list);

ArrayListIterator *array_list_create_iterator(ArrayList *list);
bool array_list_iterator_next(ArrayListIterator *iterator, void *data);
void array_list_iterator_free(ArrayListIterator *iterator);

#endif
