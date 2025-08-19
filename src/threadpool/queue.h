#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct Queue Queue;

Queue *queue_new(size_t item_size);
void queue_free(Queue *queue);

bool queue_enqueue(Queue *queue, void *data);
bool queue_fetch_count_and_enqueue(Queue *queue, void *data, size_t *old_entry_count);

bool queue_try_dequeue(Queue *queue, void *result);
bool queue_fetch_count_and_try_dequeue(Queue *queue, void *result, size_t *old_entry_count);

void queue_dequeue(Queue *queue, void *result);
void queue_fetch_count_and_dequeue(Queue *queue, void *result, size_t *old_entry_count);

#endif
