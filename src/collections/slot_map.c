#include "collections/slot_map.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_SLOT_COUNT 32
#define SCALING_FACTOR 1.5

/**
 * Stores data in slots accessed using revision and index.
 * Is mostly multithreaded, except a single entry MUST not be released
 * if it is being read by another thread.
 */

typedef struct{
    atomic_flag used;
    uint32_t revision;
    uint8_t data[];
}Slot;

struct SlotMap{
    uint8_t *slots;
    size_t slot_count;
    size_t entry_size;
    size_t slot_size;
    pthread_rwlock_t lock;
};

struct SlotMapIterator{
    SlotMap *slot_map;
    size_t index;
};

SlotMap *slot_map_new(size_t entry_size){
    SlotMap *slot_map = malloc(sizeof(SlotMap));
    size_t slot_size = entry_size + sizeof(Slot);
    uint8_t *slots = calloc(DEFAULT_SLOT_COUNT, slot_size);

    if(slot_map == NULL || slots == NULL){
        goto exit;
    }

    *slot_map = (SlotMap){
        .slots = slots,
        .slot_count = DEFAULT_SLOT_COUNT,
        .entry_size = entry_size,
        .slot_size = slot_size,
    };

    if(pthread_rwlock_init(&slot_map->lock, 0) != 0){
        goto exit;
    }

    return slot_map;

exit:
    free(slot_map);
    free(slots);
    return NULL;
}

void slot_map_free(SlotMap *slot_map){
    if(slot_map == NULL){
        return;
    }

    pthread_rwlock_destroy(&slot_map->lock);
    free(slot_map->slots);
    free(slot_map);
}

bool _resize(SlotMap *slot_map){
    size_t prev_count = slot_map->slot_count;
    pthread_rwlock_wrlock(&slot_map->lock);

    if(slot_map->slot_count > prev_count){
        pthread_rwlock_unlock(&slot_map->lock);
        return true;
    }

    size_t new_count = slot_map->slot_count * SCALING_FACTOR;
    assert(new_count > slot_map->slot_count);
    uint8_t *new_slots = calloc(new_count, slot_map->slot_size);

    if(new_slots == NULL){
        pthread_rwlock_unlock(&slot_map->lock);
        return false;
    }

    memcpy(new_slots, slot_map->slots, slot_map->slot_count * slot_map->slot_size);
    free(slot_map->slots);
    slot_map->slots = new_slots;
    slot_map->slot_count = new_count;

    pthread_rwlock_unlock(&slot_map->lock);
    return true;
}

bool _try_get_handle(SlotMap *slot_map, SlotMapHandle *result){
    for(size_t i = 0; i < slot_map->slot_count; i++){
        Slot *slot = (Slot *)(slot_map->slots + i * slot_map->slot_size);
        bool was_used = atomic_flag_test_and_set(&slot->used);
        if(!was_used){
            *result = (SlotMapHandle){
                .index = i,
                .revision = slot->revision
            };
            return true;
        }
    }
    return false;
}

bool slot_map_try_add(SlotMap *slot_map, void *data, SlotMapHandle *result){
    for(size_t i = 0; i < 4096; i++){
        pthread_rwlock_rdlock(&slot_map->lock);
        if(_try_get_handle(slot_map, result)){
            Slot *slot = (Slot *)(slot_map->slots + result->index * slot_map->slot_size);
            memcpy(slot->data, data, slot_map->entry_size);
            pthread_rwlock_unlock(&slot_map->lock);
            return true;
        }
        pthread_rwlock_unlock(&slot_map->lock);
        if(!_resize(slot_map)){
            return false;
        }
    }

    assert(false && "Unable to add slot map entry in 4096 attemts");
    return false;
}

bool slot_map_try_get(SlotMap *slot_map, SlotMapHandle handle, void *result){
    pthread_rwlock_rdlock(&slot_map->lock);
    if(handle.index >= slot_map->slot_count){
        goto exit_failure;
    }
    Slot *slot = (Slot *)(slot_map->slots + handle.index * slot_map->slot_size);
    if(slot->revision != handle.revision){
        goto exit_failure;
    }
    memcpy(result, slot->data, slot_map->entry_size);
    pthread_rwlock_unlock(&slot_map->lock);
    return true;


exit_failure:
    pthread_rwlock_unlock(&slot_map->lock);
    return false;
}

void slot_map_remove(SlotMap *slot_map, SlotMapHandle handle){
    pthread_rwlock_rdlock(&slot_map->lock);
    if(handle.index >= slot_map->slot_count){
        goto exit;
    }
    Slot *slot = (Slot *)(slot_map->slots + handle.index * slot_map->slot_size);
    if(slot->revision != handle.revision){
        goto exit;
    }
    slot->revision++;
    atomic_flag_clear(&slot->used);
exit:
    pthread_rwlock_unlock(&slot_map->lock);
}


SlotMapIterator *slot_map_create_iterator(SlotMap *slot_map){
    SlotMapIterator *iterator = malloc(sizeof(SlotMapIterator));
    if(iterator == NULL){
        return NULL;
    }
    *iterator = (SlotMapIterator){
        .index = 0,
        .slot_map = slot_map
    };

    return iterator;
}

bool slot_map_iterator_next(SlotMapIterator *iterator, void *result){
    SlotMap *slot_map = iterator->slot_map;

    pthread_rwlock_rdlock(&slot_map->lock);

    while(iterator->index < slot_map->slot_count){
        Slot *slot = (Slot *)(slot_map->slots + iterator->index * slot_map->slot_size);
        iterator->index++;
        bool is_set = atomic_flag_test_and_set(&slot->used);
        if(is_set){
            memcpy(result, slot->data, slot_map->entry_size);
            pthread_rwlock_unlock(&slot_map->lock);
            return true;
        }
        else{
            atomic_flag_clear(&slot->used);
        }
    }
    pthread_rwlock_unlock(&slot_map->lock);
    return false;
}

void slot_map_iterator_free(SlotMapIterator *iterator){
    free(iterator);
}
