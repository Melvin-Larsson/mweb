#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <stdbool.h>
typedef struct ThreadPool ThreadPool;

typedef struct{
    int index;
    int revision;
}ThreadPoolQueue;

typedef enum{
    ThreadPoolStatusOk,
    ThreadPoolStatusQueueDoesNotExist,
    ThreadPoolStatusOutOfMemory
}ThreadPoolStatus;

ThreadPool *threadpool_new();
void threadpool_free(ThreadPool *thread_pool);

bool threadpool_try_create_new_queue(ThreadPool *threadpool, ThreadPoolQueue *queue);
void threadpool_release_queue(ThreadPool *threadpool, ThreadPoolQueue queue);
ThreadPoolStatus threadpool_enqueue_work(ThreadPool *threadpool, ThreadPoolQueue queue, void (*callback)(void *u_data), void *u_data);

#endif
