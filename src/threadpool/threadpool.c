#include "threadpool/threadpool.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "queue.h"

#define DEFAULT_QUEUE_COUNT 32
#define QUEUE_COUNT_SCALING_FACTOR 1.5

typedef enum{
    Function,
    StopSignalItem
}QueueItemType;

typedef struct{
    QueueItemType type;
    ThreadPoolQueue client_queue;
}GlobalQueueItem;

typedef struct{
    void (*invode)(void *u_data);
    void *u_data;
}QueueItem;

typedef struct{
    Queue *queue;
    atomic_int revision;
    atomic_flag used;
    pthread_rwlock_t lock;
}QueueEntry;

typedef struct{
    size_t count;
    QueueEntry *entries;
    pthread_rwlock_t lock;
}QueueList;

struct ThreadPool{
    volatile bool stopping;

    QueueList queues;
    Queue *global_queue;

    pthread_t *threads;
    size_t thread_count;
};

bool _init_queue_list(QueueList *queue);
void _clear_queue_list(QueueList *queue);

bool _queue_list_get_free_entry(QueueList *queue_list, ThreadPoolQueue *result);
QueueEntry *_queue_list_aquire_queue_entry(QueueList *queue_list, ThreadPoolQueue queue);
Queue *_queue_list_aquire_queue(QueueList *queue_list, ThreadPoolQueue queue);
void _queue_list_release_queue(QueueList *queue_list, ThreadPoolQueue queue);
void _queue_list_release_queue_entry(QueueList *queue_list, QueueEntry *entry);
void _queue_list_remove_entry(QueueList *queues, ThreadPoolQueue queue);

static void *_run(void *);

ThreadPool *threadpool_new(){
    ThreadPool *thread_pool = malloc(sizeof(ThreadPool));
    if(thread_pool == NULL){
        return NULL;
    }

    size_t thread_count = 8;
    *thread_pool = (ThreadPool){
        .stopping = false,
        .thread_count = thread_count,
        .global_queue = queue_new(sizeof(GlobalQueueItem)),
        .threads = malloc(sizeof(pthread_t) * thread_count)
    };

    if(thread_pool->global_queue == NULL || thread_pool->threads == NULL){
        goto exit;
    }

    if(!_init_queue_list(&thread_pool->queues)){
        goto exit;
    }

    size_t i = 0;
    for(; i < thread_count; i++){
        if(pthread_create(&thread_pool->threads[i], 0, _run, thread_pool) != 0){
            break;
        }
    }
    if(i == 0){
        goto exit_queue_list;
    }

    if(i < thread_count){
        thread_pool->thread_count = i;
        printf("Unable to create %zu threads, only %zu threads was created\n", thread_count, thread_pool->thread_count);
    }

    return thread_pool;

exit_queue_list:
    _clear_queue_list(&thread_pool->queues);
exit:
    free(thread_pool);
    queue_free(thread_pool->global_queue);
    free(thread_pool->threads);
    return NULL;
}

void threadpool_free(ThreadPool *thread_pool){
    if(thread_pool == NULL){
        return;
    }
    thread_pool->stopping = true;
    GlobalQueueItem item = {
        .client_queue = {0, 0},
        .type = StopSignalItem
    };
    printf("Stopping threads...\n");
    for(size_t i = 0; i < thread_pool->thread_count; i++){
        queue_enqueue(thread_pool->global_queue, &item);
    }
    for(size_t i = 0; i < thread_pool->thread_count; i++){
        pthread_join(thread_pool->threads[i], NULL);
        printf("Thread %zu stopped\n", i);
    }

    free(thread_pool->threads);
    queue_free(thread_pool->global_queue);
    _clear_queue_list(&thread_pool->queues);
    free(thread_pool);
}

static void *_run(void *data){
    ThreadPool *thread_pool = (ThreadPool *)data;
    while(!thread_pool->stopping){
        GlobalQueueItem global_item;
        queue_dequeue(thread_pool->global_queue, &global_item);
        if(global_item.type == StopSignalItem){
            return NULL;
        }

        Queue *queue = _queue_list_aquire_queue(&thread_pool->queues, global_item.client_queue);
        if(queue == NULL){
            continue;
        }

        QueueItem item;
        size_t old_count;
        bool success = queue_fetch_count_and_try_dequeue(queue, &item, &old_count);
        _queue_list_release_queue(&thread_pool->queues, global_item.client_queue);
        if(!success){
            continue;
        }
        assert(item.invode != NULL);
        item.invode(item.u_data);

        if(old_count > 1){
            queue_enqueue(thread_pool->global_queue, &global_item);
        }
    }

    return NULL;
}

bool threadpool_try_create_new_queue(ThreadPool *threadpool, ThreadPoolQueue *queue){
    if(!_queue_list_get_free_entry(&threadpool->queues, queue)){
        assert(false && "Failed to find entry for Queue in queue list");
        return false;
    }

    QueueEntry *queue_entry = _queue_list_aquire_queue_entry(&threadpool->queues, *queue);
    if(queue_entry == NULL){ //This should not happen
        assert(false && "New queue entry has become invalid");
        return false;
    }

    assert(queue_entry->queue == NULL);

    queue_entry->queue = queue_new(sizeof(QueueItem));
    bool result = true;
    if(queue_entry->queue == NULL){
        assert(false && "Failed to create new queue");
        atomic_flag_clear(&queue_entry->used);
        result = false;
    }

    _queue_list_release_queue_entry(&threadpool->queues, queue_entry);
    return result;
}

ThreadPoolStatus threadpool_enqueue_work(ThreadPool *threadpool, ThreadPoolQueue queue_handle, void (*callback)(void *u_data), void *u_data){
    Queue *queue = _queue_list_aquire_queue(&threadpool->queues, queue_handle);
    if(queue == NULL){
        return ThreadPoolStatusQueueDoesNotExist;
    }

    QueueItem item = {
        .invode = callback,
        .u_data = u_data
    };
    size_t old_count;
    if(!queue_fetch_count_and_enqueue(queue, &item, &old_count)){
        assert(false && "Unable to enqueue item");
        _queue_list_release_queue(&threadpool->queues, queue_handle);
        return ThreadPoolStatusOutOfMemory;
    }
    if(old_count == 0){
        GlobalQueueItem gqi = {
            .type = Function,
            .client_queue = queue_handle
        };
        queue_enqueue(threadpool->global_queue, &gqi);
    }

    _queue_list_release_queue(&threadpool->queues, queue_handle);
    return ThreadPoolStatusOk;
}

void threadpool_release_queue(ThreadPool *threadpool, ThreadPoolQueue queue_handle){
    _queue_list_remove_entry(&threadpool->queues, queue_handle); 
}

bool _init_queue_list(QueueList *queue_list){
    *queue_list = (QueueList){
        .count = DEFAULT_QUEUE_COUNT,
        .entries = calloc(DEFAULT_QUEUE_COUNT, sizeof(QueueEntry)),
    };
    if(pthread_rwlock_init(&queue_list->lock, 0) != 0){
        free(queue_list->entries);
        return false;
    }
    return queue_list->entries != NULL;
}

void _clear_queue_list(QueueList *queue){
    if(queue == NULL){
        return;
    }
    if(pthread_rwlock_trywrlock(&queue->lock) != 0){
        assert(false && "Unable to clear queue list when it is being used");
    }
    pthread_rwlock_wrlock(&queue->lock);
    for(size_t i = 0; i < queue->count; i++){
        QueueEntry *entry = &queue->entries[i];
        if(atomic_flag_test_and_set(&entry->used)){
            pthread_rwlock_destroy(&entry->lock);
            queue_free(entry->queue);
        }
    }
    free(queue->entries);
    pthread_rwlock_unlock(&queue->lock);

    pthread_rwlock_destroy(&queue->lock);
}

bool _queue_list_resize(QueueList *queues){
    size_t entry_count_before = queues->count;

    pthread_rwlock_wrlock(&queues->lock);

    if(queues->count > entry_count_before){
        pthread_rwlock_unlock(&queues->lock);
        return true;
    }

    size_t new_count = queues->count * QUEUE_COUNT_SCALING_FACTOR;
    assert(new_count > queues->count);
    QueueEntry *new_list = calloc(new_count, sizeof(QueueEntry));
    if(new_list == NULL){
        pthread_rwlock_unlock(&queues->lock);
        return false;
    }
    memcpy(new_list, queues->entries, queues->count * sizeof(QueueEntry));
    printf("Free queue list\n");
    free(queues->entries);
    printf("queue list freed\n");
    queues->entries = new_list;
    queues->count = new_count;

    pthread_rwlock_unlock(&queues->lock);
    return true;
}

bool _queue_list_get_free_entry(QueueList *queue_list, ThreadPoolQueue *result){
    pthread_rwlock_rdlock(&queue_list->lock);
    for(size_t i = 0; i < queue_list->count; i++){
        QueueEntry *entry = &queue_list->entries[i];
        bool was_used = atomic_flag_test_and_set(&entry->used);
        if(!was_used){
            *result = (ThreadPoolQueue){
                .index = i,
                .revision = atomic_load(&entry->revision)
            };
            pthread_rwlock_unlock(&queue_list->lock);
            return true;
        }
    }
    pthread_rwlock_unlock(&queue_list->lock);

    if(!_queue_list_resize(queue_list)){
        return false;
    }
    return _queue_list_get_free_entry(queue_list, result);
}

void _queue_list_remove_entry(QueueList *queues, ThreadPoolQueue queue){
    pthread_rwlock_rdlock(&queues->lock);
    assert(queue.index < queues->count);

    QueueEntry *entry = &queues->entries[queue.index];
    if(!atomic_compare_exchange_strong(&entry->revision, &queue.revision, queue.revision + 1)){
        pthread_rwlock_unlock(&queues->lock);
        return;
    }

    printf("Freesing index %d, rev %d\n", queue.index, queue.revision);
    pthread_rwlock_wrlock(&entry->lock);
    printf("Free queue\n");
    queue_free(entry->queue);
    printf("queue freed\n");
    entry->queue = NULL;
    atomic_flag_clear(&entry->used);

    pthread_rwlock_unlock(&entry->lock);
    pthread_rwlock_unlock(&queues->lock);
}

Queue *_queue_list_aquire_queue(QueueList *queue_list, ThreadPoolQueue queue){
    Queue *result = NULL;
    pthread_rwlock_rdlock(&queue_list->lock);
    if(queue.index >= queue_list->count){
        goto exit;
    }
    QueueEntry *entry = &queue_list->entries[queue.index];
    pthread_rwlock_rdlock(&entry->lock);
    if(entry->revision != queue.revision){
        pthread_rwlock_unlock(&entry->lock);
        goto exit;
    }
    result = entry->queue;
exit:
    pthread_rwlock_unlock(&queue_list->lock);
    return result;
}

QueueEntry *_queue_list_aquire_queue_entry(QueueList *queue_list, ThreadPoolQueue queue){
    pthread_rwlock_rdlock(&queue_list->lock);
    if(queue.index >= queue_list->count){
        pthread_rwlock_unlock(&queue_list->lock);
        return NULL;
    }
    QueueEntry *entry = &queue_list->entries[queue.index];
    if(entry->revision != queue.revision){
        pthread_rwlock_unlock(&queue_list->lock);
        return NULL;
    }
    return entry;
}

void _queue_list_release_queue(QueueList *queue_list, ThreadPoolQueue queue){
    pthread_rwlock_rdlock(&queue_list->lock);
    if(queue.index >= queue_list->count){
        goto exit;
    }
    QueueEntry *entry = &queue_list->entries[queue.index];
    pthread_rwlock_unlock(&entry->lock);
exit:
    pthread_rwlock_unlock(&queue_list->lock);
}

void _queue_list_release_queue_entry(QueueList *queue_list, QueueEntry *entry){
    pthread_rwlock_unlock(&queue_list->lock);
}
