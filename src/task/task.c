#include "task/task.h" 
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_EXTENDED_TASK_LIST_SIZE TASK_LIST_STACK_TASK_COUNT
#define TASK_LIST_GROWTH_FACTOR 1.5

void task_list_init(TaskList *task_list){
    *task_list = (TaskList){
        .task_count = 0,
        ._dequeue = 0,
        ._tasks = {0},
        ._extended_tasks = NULL,
        ._extended_task_buffer_count = 0
    };
}

void task_list_clear(TaskList *task_list){
    if(task_list == NULL){
        return;
    }
    free(task_list->_extended_tasks);
    *task_list = (TaskList){
        .task_count = 0,
        ._dequeue = 0,
        ._tasks = {0},
        ._extended_tasks = NULL,
        ._extended_task_buffer_count = 0
    };
}

bool task_list_try_dequeue(TaskList *task_list, Task *result){
    if(task_list->_dequeue >= task_list->task_count){
        return false;
    }
    if(task_list->_dequeue < TASK_LIST_STACK_TASK_COUNT){
        *result = task_list->_tasks[task_list->_dequeue++];
        return true;
    }
    size_t index = task_list->_dequeue++ - TASK_LIST_STACK_TASK_COUNT;
    *result = task_list->_extended_tasks[index];

    return true;
}

bool task_list_add_task(TaskList *task_list, Task task){
    if(task.complete){
        return true;
    }

    if(task_list->task_count < TASK_LIST_STACK_TASK_COUNT){
        task_list->_tasks[task_list->task_count++] = task;
        return true;
    }
    else if(task_list->task_count == TASK_LIST_STACK_TASK_COUNT){
        task_list->_extended_tasks = calloc(DEFAULT_EXTENDED_TASK_LIST_SIZE, sizeof(Task));
        if(task_list->_extended_tasks == NULL){
            return false;
        }
        task_list->_extended_task_buffer_count = DEFAULT_EXTENDED_TASK_LIST_SIZE;
    }
    else if(task_list->task_count == task_list->_extended_task_buffer_count + TASK_LIST_STACK_TASK_COUNT){
        size_t new_count = task_list->_extended_task_buffer_count * TASK_LIST_GROWTH_FACTOR;
        assert(new_count > task_list->_extended_task_buffer_count);
        Task *new_extended_list = calloc(new_count, sizeof(Task));
        if(new_extended_list == NULL){
            return false;
        }
        memcpy(new_extended_list, task_list->_extended_tasks, task_list->_extended_task_buffer_count * sizeof(Task));
        free(task_list->_extended_tasks);
        task_list->_extended_tasks = new_extended_list;
        task_list->_extended_task_buffer_count = new_count;
    }

    task_list->_extended_tasks[task_list->task_count++ - TASK_LIST_STACK_TASK_COUNT] = task;

    return true;
}
