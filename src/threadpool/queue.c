#include "queue.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_QUEUE_SIZE 8
#define QUEUE_SCALING_FACTOR 1.5

typedef struct{
    atomic_size_t seq;
    char data[]; 
}Slot;

struct Queue{
    uint8_t *data;
    atomic_size_t enqueue;
    atomic_size_t dequeue;
    size_t entry_count;
    size_t item_size;
    size_t slot_size;
    pthread_rwlock_t lock;
    pthread_mutex_t dequeu_mutex;
    pthread_cond_t queue_not_empty_cond;

    atomic_size_t count;
};

Queue *queue_new(size_t item_size){
    Queue *queue = malloc(sizeof(Queue));
    uint8_t *data = malloc((sizeof(Slot) + item_size) * DEFAULT_QUEUE_SIZE);
    bool lock_created = pthread_rwlock_init(&queue->lock, 0) == 0;
    bool mutex_created = pthread_mutex_init(&queue->dequeu_mutex, 0) == 0;
    bool cond_created = pthread_cond_init(&queue->queue_not_empty_cond, 0) == 0;

    if(!lock_created || !mutex_created || !cond_created || queue == NULL || data == NULL){
        free(queue);
        free(data);
        if(lock_created){
            pthread_rwlock_destroy(&queue->lock);
        }
        if(mutex_created){
            pthread_mutex_destroy(&queue->dequeu_mutex);
        }
        if(cond_created){
            pthread_cond_destroy(&queue->queue_not_empty_cond);
        }
        return NULL;
    }

    queue->data = data;
    queue->item_size = item_size;
    queue->slot_size = item_size + sizeof(Slot);
    queue->enqueue = 0;
    queue->dequeue = 0;
    queue->entry_count = DEFAULT_QUEUE_SIZE;
    queue->count = 0;

    for(size_t i = 0; i < queue->entry_count; i++){
        Slot *slot = (Slot *)(queue->data + i * queue->slot_size);
        slot->seq = i;
    }

    return queue;
}

void queue_free(Queue *queue){
    if(queue == NULL){
        return;
    }

    free(queue->data);
    pthread_rwlock_destroy(&queue->lock);
    pthread_mutex_destroy(&queue->dequeu_mutex);
    pthread_cond_destroy(&queue->queue_not_empty_cond);
    free(queue);
}

size_t queue_get_size(Queue *queue){
    pthread_rwlock_rdlock(&queue->lock);

    size_t enqueue = atomic_load(&queue->enqueue);
    size_t dequeu = atomic_load(&queue->dequeue);
    size_t result = enqueue - dequeu;

    pthread_rwlock_unlock(&queue->lock);

    return result;
}

bool _resize_queue(Queue *queue){
    size_t count_before = queue->entry_count;
    pthread_rwlock_wrlock(&queue->lock);
    if(queue->entry_count > count_before){
        pthread_rwlock_unlock(&queue->lock);
        return true;
    }

    size_t new_entry_count = queue->entry_count * QUEUE_SCALING_FACTOR;
    assert(new_entry_count > queue->entry_count);
    uint8_t *new_buffer = calloc(new_entry_count, queue->slot_size);
    if(new_buffer == NULL){
        pthread_rwlock_unlock(&queue->lock);
        return false;
    }

    size_t head = queue->dequeue;
    size_t tail = queue->enqueue;
    size_t count = tail - head;

    uint8_t *old_buf = queue->data;
    uint8_t *new_buf = new_buffer;

    size_t items_before_wrap = queue->entry_count - (head % queue->entry_count);
    if (items_before_wrap > count) {
        items_before_wrap = count;
    }
    size_t items_after_wrap = count - items_before_wrap;

    memcpy(new_buf, old_buf + (head % queue->entry_count) * queue->slot_size, items_before_wrap * queue->slot_size);

    if (items_after_wrap > 0) {
        memcpy(new_buf + items_before_wrap * queue->slot_size, old_buf, items_after_wrap * queue->slot_size);
    }

    queue->dequeue = 0;
    queue->enqueue = count;

    for (size_t i = 0; i < count; i++) {
        Slot *slot = (Slot *)(new_buf + i * queue->slot_size);
        slot->seq = i + 1;
    }
    for (size_t i = count; i < new_entry_count; i++) {
        Slot *slot = (Slot *)(new_buf + i * queue->slot_size);
        slot->seq = i;
    }

    free(old_buf);
    queue->data = new_buf;
    queue->entry_count = new_entry_count;

    pthread_rwlock_unlock(&queue->lock);
    return true;
}

bool queue_fetch_count_and_enqueue(Queue *queue, void *data, size_t *old_entry_count){
    atomic_fetch_add(&queue->count, 1);
    for(size_t i = 0; i < 4096; i++){
        pthread_rwlock_rdlock(&queue->lock);
        size_t enqueue_flat = atomic_load(&queue->enqueue);
        size_t enqueue_slot = enqueue_flat % queue->entry_count;
        Slot *slot = (Slot *)(queue->data + enqueue_slot * queue->slot_size);
        size_t seq = atomic_load(&slot->seq);

        intptr_t diff = (intptr_t)seq - (intptr_t)enqueue_flat;

        if(diff == 0){
            if(atomic_compare_exchange_strong(&queue->enqueue, &enqueue_flat, enqueue_flat + 1)){
                memcpy(slot->data, data, queue->item_size);
                atomic_store(&slot->seq, seq + 1);
                *old_entry_count = enqueue_flat - atomic_load(&queue->dequeue);
                pthread_cond_signal(&queue->queue_not_empty_cond);
                pthread_rwlock_unlock(&queue->lock);
                return true;
            }
            pthread_rwlock_unlock(&queue->lock);
        }
        else{
            pthread_rwlock_unlock(&queue->lock);
            if(diff < 0){
                if(!_resize_queue(queue)){
                    return false;
                }
            }
        }
    }

    assert(false && "queue_enqueue exceeded max attempts");
    return false;
}

bool queue_enqueue(Queue *queue, void *data){
    size_t old_entry_count;
    return queue_fetch_count_and_enqueue(queue, data, &old_entry_count);
}

bool queue_try_dequeue(Queue *queue, void *result){
    size_t old_entry_count;
    return queue_fetch_count_and_try_dequeue(queue, result, &old_entry_count);
}

bool queue_fetch_count_and_try_dequeue(Queue *queue, void *result, size_t *old_entry_count){
    *old_entry_count = 0;
    for(size_t i = 0; i < 4096; i++){
        pthread_rwlock_rdlock(&queue->lock);
        size_t dequeue_flat = atomic_load(&queue->dequeue);
        size_t dequeue = dequeue_flat % queue->entry_count;
        Slot *slot = (Slot *)(queue->data + dequeue * queue->slot_size);
        size_t seq = atomic_load(&slot->seq);

        intptr_t diff = (intptr_t)seq - (intptr_t)(dequeue_flat + 1);
        if(diff == 0){
            if(atomic_compare_exchange_strong(&queue->dequeue, &dequeue_flat, dequeue_flat + 1)){
                memcpy(result, slot->data, queue->item_size);
                atomic_store(&slot->seq, dequeue_flat + queue->entry_count);
                *old_entry_count = atomic_load(&queue->enqueue) - dequeue_flat;
                pthread_rwlock_unlock(&queue->lock);
                return true;
            }
            pthread_rwlock_unlock(&queue->lock);
        }
        else{
            pthread_rwlock_unlock(&queue->lock);
            if(diff < 0){
                return false;
            }
        }
    }

    return false;
}

void queue_dequeue(Queue *queue, void *result){
    size_t old_entry_count;
    queue_fetch_count_and_dequeue(queue, result, &old_entry_count);
}

void queue_fetch_count_and_dequeue(Queue *queue, void *result, size_t *old_entry_count){
    pthread_mutex_lock(&queue->dequeu_mutex);
    while(!queue_fetch_count_and_try_dequeue(queue, result, old_entry_count)){
        pthread_cond_wait(&queue->queue_not_empty_cond, &queue->dequeu_mutex);
    }
    pthread_mutex_unlock(&queue->dequeu_mutex);
}

size_t queue_size(Queue *queue){
    pthread_rwlock_rdlock(&queue->lock);
    size_t dequeue = atomic_load(&queue->dequeue);
    size_t enqueue = atomic_load(&queue->enqueue);
    pthread_rwlock_unlock(&queue->lock);
    return enqueue - dequeue;
}
