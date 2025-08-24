#ifndef TASK_H
#define TASK_H

#include "io_uring/io_uring.h"

#define TASK_LIST_STACK_TASK_COUNT 4

typedef enum{
    TaskTypeWork,
    TaskTypeEvent,
    TaskTypeUring
}TaskType;

typedef struct{
    void (*invoke)(void *ctx);
    void *ctx;
}WorkTask;

typedef struct{
    void (*callback)(void *ctx);
    void *ctx;
    int fd;
}EventTask;

typedef struct{
    void (*callback)(void *ctx);
    void *ctx;
    IoUringOp op;
}UringTask;

typedef struct{
    TaskType type;
    bool complete;
    union{
        WorkTask work_task;
        EventTask event_task;
        UringTask uring_task;
    };
}Task;

typedef struct{
    size_t task_count;
    size_t _dequeue;
    Task _tasks[TASK_LIST_STACK_TASK_COUNT];
    Task *_extended_tasks;
    size_t _extended_task_buffer_count;
}TaskList;

void task_list_init(TaskList *task_list);
void task_list_clear(TaskList *task_list);
bool task_list_try_dequeue(TaskList *task_list, Task *result);
bool task_list_add_task(TaskList *task_list, Task task);

static inline TaskList task_list_empty(){
    TaskList list;
    task_list_init(&list);
    return list;
}

static inline Task event_task(void (*callback)(void *), void *ctx, int fd){
    return (Task) {
        .type = TaskTypeEvent,
        .complete = false,
        .event_task = (EventTask){
            .callback = callback,
            .ctx = ctx,
            .fd = fd
        }
    };
}

static inline Task work_task(void (*worker)(void *), void *ctx){
    return (Task) {
        .type = TaskTypeWork,
        .complete = false,
        .work_task = (WorkTask){
            .invoke = worker,
            .ctx = ctx,
        }
    };
}

static inline Task io_uring_task(void (*worker)(void *), void *ctx, IoUringOp op){
    return (Task) {
        .type = TaskTypeUring,
        .complete = false,
        .uring_task = (UringTask){
            .callback = worker,
            .ctx = ctx,
            .op = op
        }
    };
}

static inline Task completed_task(){
    return (Task) {
        .type = TaskTypeWork,
        .complete = true,
    };
}

#endif
