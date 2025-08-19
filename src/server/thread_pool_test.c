#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include "threadpool/threadpool.h"  // your header file for the threadpool

#define MAX_QUEUES 5
#define MAX_WORK_ITEMS 50

typedef struct {
    int queue_num;
    int work_num;
} WorkData;

void work_callback(void *u_data) {
    WorkData *data = (WorkData *)u_data;
    printf("Queue %d: executing work item %d\n", data->queue_num, data->work_num);
    usleep(rand() % 100000); // random sleep up to 0.1s
    free(data);
}

void *chaotic_thread(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;
    ThreadPoolQueue queues[MAX_QUEUES];
    size_t num_queues = 0;

    while (1) {
        ThreadPoolQueue queue;

        // Decide randomly whether to create a new queue or reuse an existing one
        if (num_queues < MAX_QUEUES && (rand() % 2 == 0 || num_queues == 0)) {
            if (threadpool_try_create_new_queue(pool, &queue)) {
                queues[num_queues++] = queue;
            }
        } else {
            // Pick an existing queue at random
            queue = queues[rand() % num_queues];
        }

        // Add work to the chosen queue
        int work_items = rand() % MAX_WORK_ITEMS + 1;
        for (int i = 0; i < work_items; i++) {
            WorkData *data = malloc(sizeof(WorkData));
            data->queue_num = queue.index;
            data->work_num = i;
            threadpool_enqueue_work(pool, queue, work_callback, data);
        }

        // Occasionally release a queue (only if we have multiple)
        if (num_queues > 1 && rand() % 10 == 0) {
            size_t idx = rand() % num_queues;
            threadpool_release_queue(pool, queues[idx]);
            // Remove from array
            queues[idx] = queues[--num_queues];
        }

        usleep(rand() % 500000); // short random pause
    }

    return NULL;
}

int chaotic_test() {
    srand(time(NULL));

    ThreadPool *pool = threadpool_new();
    if (!pool) {
        fprintf(stderr, "Failed to create thread pool\n");
        return 1;
    }

    // create multiple threads that will randomly create queues and add work
    pthread_t threads[10];
    for (int i = 0; i < 10; i++) {
        pthread_create(&threads[i], NULL, chaotic_thread, pool);
    }

    // run for some time
    sleep(5);

    printf("==========================================Shutting down...\n");

    for (int i = 0; i < 10; i++) {
        printf("Stopping test thread %d\n", i);
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
        printf("Stopped test thread %d\n", i);
    }

    printf("Stopping threadpool\n");
    threadpool_free(pool);
    return 0;
}
