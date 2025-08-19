#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>   // sleep
#include <assert.h>

// ---- Queue interface (your implementation elsewhere) ----
typedef struct Queue Queue;
Queue *queue_new(size_t item_size);
void queue_free(Queue *queue);
bool queue_enqueue(Queue *queue, void *data);
bool queue_try_dequeue(Queue *queue, void *result);
void queue_dequeue(Queue *queue, void *result);

// ---- Test harness ----
typedef struct {
    Queue *q;
    int id;
    atomic_bool *stop;
    atomic_ulong *produce_count;
} ProducerArgs;

typedef struct {
    Queue *q;
    atomic_bool *stop;
    atomic_ulong *consume_count;
} ConsumerArgs;

void *producer_thread(void *arg) {
    ProducerArgs *pa = (ProducerArgs *)arg;
    uint64_t counter = 0;
    while (!atomic_load(pa->stop)) {
        uint64_t value = ((uint64_t)pa->id << 32) | counter++;
        if (queue_enqueue(pa->q, &value)) {
            atomic_fetch_add(pa->produce_count, 1);
        }
        // Optional: small pause to mix timings
        if ((counter & 0xFFF) == 0) sched_yield();
    }
    return NULL;
}

void *consumer_thread(void *arg) {
    ConsumerArgs *ca = (ConsumerArgs *)arg;
    uint64_t value;
    while (!atomic_load(ca->stop)) {
        if (queue_try_dequeue(ca->q, &value)) {
            // Optionally validate value, e.g., push into a set
            atomic_fetch_add(ca->consume_count, 1);
        } else {
            sched_yield(); // avoid burning CPU if empty
        }
    }
    return NULL;
}

int queue_test(void) {
    const int NUM_PRODUCERS = 4;
    const int NUM_CONSUMERS = 4;
    const int SECONDS = 5;

    Queue *q = queue_new(sizeof(uint64_t));
    assert(q);

    atomic_bool stop_producers = false;
    atomic_bool stop_consumers = false;
    atomic_ulong produce_count = 0;
    atomic_ulong consume_count = 0;

    pthread_t producers[NUM_PRODUCERS];
    pthread_t consumers[NUM_CONSUMERS];

    for (int i = 0; i < NUM_PRODUCERS; i++) {
        ProducerArgs *pa = malloc(sizeof(*pa));
        pa->q = q;
        pa->id = i;
        pa->stop = &stop_producers;
        pa->produce_count = &produce_count;
        pthread_create(&producers[i], NULL, producer_thread, pa);
    }
    for (int i = 0; i < NUM_CONSUMERS; i++) {
        ConsumerArgs *ca = malloc(sizeof(*ca));
        ca->q = q;
        ca->stop = &stop_consumers;
        ca->consume_count = &consume_count;
        pthread_create(&consumers[i], NULL, consumer_thread, ca);
    }

    printf("Running chaos test for %d seconds...\n", SECONDS);
    sleep(SECONDS);
    atomic_store(&stop_producers, true);
    printf("Stopped procuders, runnings only consumers for %ds econds...\n", SECONDS);
    sleep(SECONDS);
    atomic_store(&stop_consumers, true);

    for (int i = 0; i < NUM_PRODUCERS; i++) pthread_join(producers[i], NULL);
    for (int i = 0; i < NUM_CONSUMERS; i++) pthread_join(consumers[i], NULL);

    printf("Produced: %lu, Consumed: %lu\n",
           (unsigned long)produce_count, (unsigned long)consume_count);

    queue_free(q);
    return 0;
}
