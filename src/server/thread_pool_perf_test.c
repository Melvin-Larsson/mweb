#include "threadpool/threadpool.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <unistd.h>

#define TOTAL_WORK_ITEMS 100000

typedef struct {
    int work_num;
} WorkData;

static atomic_int work_done = 0;

// Simulated CPU-bound work: calculate nth Fibonacci number iteratively
static uint64_t fib(int n) {
    if (n <= 1) return n;
    uint64_t a = 0, b = 1, c;
    for (int i = 2; i <= n; i++) {
        c = a + b;
        a = b;
        b = c;
    }
    return b;
}

// Work callback for thread pool
static void work_task(void *u_data) {
    WorkData *data = (WorkData *)u_data;

    // CPU-heavy calculation
    int n = data->work_num; // small variation per task
    volatile uint64_t result = fib(n); // volatile prevents compiler optimization
    (void)result;

    free(data);
    atomic_fetch_add(&work_done, 1);
}

#define FIB_NUM 10000

// Sequential single-threaded execution
static void run_sequential() {
    for (int i = 0; i < TOTAL_WORK_ITEMS; i++) {
        WorkData *data = malloc(sizeof(WorkData));
        data->work_num = FIB_NUM;
        work_task(data);
    }
}


typedef struct {
    int thread_id;
    int start_index;
    int end_index;
} ThreadArg;

static void *worker_thread(void *arg) {
    ThreadArg *targ = (ThreadArg *)arg;

    for (int i = targ->start_index; i < targ->end_index; i++) {
        WorkData *data = malloc(sizeof(WorkData));
        data->work_num = FIB_NUM;
        work_task(data);
        atomic_fetch_add(&work_done, 1);
    }

    return NULL;
}

// Thread pool execution
#define NUM_QUEUES 8  // Number of queues to spread work over
#define NUM_THREADS NUM_QUEUES
static void run_raw_threads() {
    pthread_t threads[NUM_THREADS];
    ThreadArg args[NUM_THREADS];

    int work_per_thread = TOTAL_WORK_ITEMS / NUM_THREADS;
    int remaining = TOTAL_WORK_ITEMS % NUM_THREADS;

    int start = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        int end = start + work_per_thread + (i < remaining ? 1 : 0);
        args[i].thread_id = i;
        args[i].start_index = start;
        args[i].end_index = end;
        pthread_create(&threads[i], NULL, worker_thread, &args[i]);
        start = end;
    }

    // Wait for threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
}


static void run_threadpool(ThreadPool *pool) {
    ThreadPoolQueue queues[NUM_QUEUES];

    // Create multiple queues
    for (int q = 0; q < NUM_QUEUES; q++) {
        if (!threadpool_try_create_new_queue(pool, &queues[q])) {
            fprintf(stderr, "Failed to create queue %d\n", q);
            return;
        }
    }

    // Distribute work across queues
    for (int i = 0; i < TOTAL_WORK_ITEMS; i++) {
        WorkData *data = malloc(sizeof(WorkData));
        assert(data != NULL);
        data->work_num = FIB_NUM;
        ThreadPoolQueue queue = queues[i % NUM_QUEUES]; // round-robin
        threadpool_enqueue_work(pool, queue, work_task, data);
    }

    // Wait for all work to finish
    while (atomic_load(&work_done) < TOTAL_WORK_ITEMS) {
        // spin-wait, or optionally sleep for a short period
        usleep(1000);
    }

    // Release queues
    for (int q = 0; q < NUM_QUEUES; q++) {
        threadpool_release_queue(pool, queues[q]);
    }
}

// Timing helper
static double timediff_sec(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

static int perf_test() {
    srand(time(NULL));

    printf("Running sequential test...\n");
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    run_sequential();
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("Sequential execution took %.3f seconds\n", timediff_sec(start, end));

    printf("Running raw threads test...\n");
    clock_gettime(CLOCK_MONOTONIC, &start);

    run_raw_threads();

    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("Raw threads execution took %.3f seconds\n", timediff_sec(start, end));
    printf("Total work done: %d\n", atomic_load(&work_done));

    work_done = 0;

    printf("Running thread pool test...\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    ThreadPool *pool = threadpool_new(); // Adjust number of threads inside threadpool_new
    run_threadpool(pool);
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("Thread pool execution took %.3f seconds\n", timediff_sec(start, end));

    threadpool_free(pool);

    work_done = 0;

    return 0;
}
