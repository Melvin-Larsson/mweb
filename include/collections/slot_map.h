#ifndef SLOT_MAP_H
#define SLOT_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct SlotMap SlotMap;
typedef struct SlotMapIterator SlotMapIterator;

typedef struct{
    uint32_t index;
    uint32_t revision;
}SlotMapHandle;

SlotMap *slot_map_new(size_t entry_size);
void slot_map_free(SlotMap *slot_map);

bool slot_map_try_add(SlotMap *slot_map, void *data, SlotMapHandle *result);
bool slot_map_try_get(SlotMap *slot_map, SlotMapHandle handle, void *result);
void slot_map_remove(SlotMap *slot_map, SlotMapHandle handle);

SlotMapIterator *slot_map_create_iterator(SlotMap *slot_map);
bool slot_map_iterator_next(SlotMapIterator *iterator, void *result);
void slot_map_iterator_free(SlotMapIterator *iterator);

#endif
