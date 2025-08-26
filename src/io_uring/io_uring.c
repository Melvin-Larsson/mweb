#include "io_uring/io_uring.h"

#include "stdbool.h"
#include "linux/io_uring.h"
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "collections/slot_map.h"
#include "errno.h"
#include "log_levels.h"

// #define USE_POLLING
#define IO_URING_ENTRY_COUNT 4096

#define max(x, y) ((x) > (y) ? (x) : (y))

#if LOG_LEVEL <= LOG_LEVEL_INFO
#define LOG_INFO(format, ...) printf("[IOUring INFO] " format "\n", ##__VA_ARGS__)
#else
#define LOG_INFO(format, ...)
#endif

#if LOG_LEVEL <= LOG_LEVEL_DEBUG
#define LOG_DEBUG(format, ...) printf("[IoUring Debug] " format "\n", ##__VA_ARGS__)
#define ERROR(format, ...) fprintf(stderr,"[IoUring Error] " format "\n", ##__VA_ARGS__)
#define ERRNO_ERROR(format, ...) fprintf(stderr,"[IoUring Error] " format "\n\t Reason: %s\n", strerror(errno), ##__VA_ARGS__)
#else
#define LOG_DEBUG(format, ...)
#define ERROR(format, ...)
#define ERRNO_ERROR(format, ...)
#endif

typedef struct{
    unsigned int *tail;
    unsigned int *array;
    unsigned int *mask;
    unsigned int *flags;
    struct io_uring_sqe *entries;
}SubmissionRing;

typedef struct{
    unsigned int *head;
    unsigned int *tail;
    unsigned int *mask;
    struct io_uring_cqe *entries;
}CompletionRing;

typedef struct{
    int uring_fd;
    SubmissionRing subbmission_ring;
    CompletionRing completion_ring;
}IoRing;

struct IoUring{
    IoRing ring;
    SlotMap *slot_map;
    int epollfd;
    int stopfd;
    int eventfd;
    pthread_t thread;
    atomic_size_t count;
    pthread_mutex_t lock;
};

void *_run(void * data);
static bool _read_from_cq(IoUring *uring, uint64_t *result);

#define io_uring_smp_store_release(p, v)            \
   atomic_store_explicit((_Atomic typeof(*(p)) *)(p), (v), \
                 memory_order_release)
#define io_uring_smp_load_acquire(p)                \
   atomic_load_explicit((_Atomic typeof(*(p)) *)(p),   \
                memory_order_acquire)

int io_uring_setup(unsigned int entries, struct io_uring_params *params){
    return syscall(__NR_io_uring_setup, entries, params);
}

int io_uring_enter(int ring_fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags){
   return syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete, flags, NULL, 0);
}
int io_uring_register(unsigned int ring_fd, unsigned int opcode, void *arg, unsigned int nr_args){
    return syscall(__NR_io_uring_register, ring_fd, opcode, arg, nr_args);
}

bool _init_epoll(IoUring *uring){
    uring->epollfd = epoll_create1(0);
    if(uring->epollfd < 0){
        ERRNO_ERROR("Failed creating epoll");
        return false;
    }

    uring->stopfd = eventfd(0, 0);
    if(uring->stopfd < 0){
        close(uring->epollfd);
        return false;
    }
    struct epoll_event stop_cfg = {
        .events = EPOLLIN,
        .data.fd = uring->stopfd
    };
    if(epoll_ctl(uring->epollfd, EPOLL_CTL_ADD, uring->stopfd, &stop_cfg) < 0){
        ERRNO_ERROR("Failed to listen on stop signal");
        close(uring->epollfd);
        close(uring->stopfd);
        return false;
    }
    uring->eventfd = eventfd(0, 0);
    if(uring->eventfd < 0){
        close(uring->epollfd);
        close(uring->stopfd);
        return false;
    }
    struct epoll_event event_cfg = {
        .events = EPOLLIN,
        .data.fd = uring->eventfd
    };
    if(epoll_ctl(uring->epollfd, EPOLL_CTL_ADD, uring->eventfd, &event_cfg) < 0){
        ERRNO_ERROR("Failed to listen on write signal");
        close(uring->epollfd);
        close(uring->stopfd);
        close(uring->eventfd);
        return false;
    }
    return true;
}

IoUring *io_uring_new(){
    IoUring *io_uring = malloc(sizeof(IoUring));
    SlotMap *slot_map = slot_map_new(sizeof(IoUringCallback));

    if(io_uring == NULL || slot_map == NULL || !_init_epoll(io_uring)){
        ERROR("Unable to allocate memory");
        goto exit_slot_map;
    }
    io_uring->slot_map = slot_map;
    if(pthread_mutex_init(&io_uring->lock, 0) != 0){
        ERROR("Unable to create io uring lock");
        goto exit_slot_map;
    }

    struct io_uring_params params = {0};
#ifdef USE_POLLING
    params.flags = IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 1000;
#endif
    int result = io_uring_setup(IO_URING_ENTRY_COUNT, &params);
    if(result < 0){
        goto exit_slot_map;
        ERROR("Unable to create setup io_uring");
    }
    io_uring->ring.uring_fd = result;

    int submission_ring_size = params.sq_off.array + params.sq_entries * sizeof(unsigned int);
    int completion_ring_size = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);

    if(params.features & IORING_FEAT_SINGLE_MMAP){
        submission_ring_size = max(submission_ring_size, completion_ring_size);
        completion_ring_size = submission_ring_size;
    }

    void *submission_queue_ptr = mmap(0, submission_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, io_uring->ring.uring_fd, IORING_OFF_SQ_RING);
    if(submission_queue_ptr == MAP_FAILED){
        ERROR("Unable to mmap submission ring");
        goto exit_slot_map;
    }

    void *completion_queue_ptr;
    if(params.features & IORING_FEAT_SINGLE_MMAP){
        completion_queue_ptr = submission_queue_ptr;
    }
    else{
        completion_queue_ptr = mmap(0, completion_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, io_uring->ring.uring_fd, IORING_OFF_CQ_RING);
        if(completion_queue_ptr == MAP_FAILED){
            ERROR("Unable to mmap completion ring");
            goto exit_slot_map;
        }
    }
    io_uring->ring.subbmission_ring = (SubmissionRing){
        .tail = submission_queue_ptr + params.sq_off.tail,
        .array = submission_queue_ptr + params.sq_off.array,
        .mask = submission_queue_ptr + params.sq_off.ring_mask,
        .flags = submission_queue_ptr + params.sq_off.flags
    };
    io_uring->ring.completion_ring = (CompletionRing){
        .head = submission_queue_ptr + params.cq_off.head,
        .tail = submission_queue_ptr + params.cq_off.tail,
        .mask = submission_queue_ptr + params.cq_off.ring_mask,
        .entries = submission_queue_ptr + params.cq_off.cqes
    };

    io_uring->ring.subbmission_ring.entries = mmap(0, params.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, io_uring->ring.uring_fd, IORING_OFF_SQES);
    if(io_uring->ring.subbmission_ring.entries == MAP_FAILED){
        ERROR("Unable to mmap submissoin entries");
        goto exit_slot_map;
    }

    int register_status = io_uring_register(io_uring->ring.uring_fd, IORING_REGISTER_EVENTFD, &io_uring->eventfd, 1);
    if(register_status < 0){
        ERROR("Unable to register eventfd for uring (Error code %d).", register_status);
        goto exit_slot_map;
    }

    if(pthread_create(&io_uring->thread, 0, _run, io_uring)){
        ERROR("Unable to create pthread");
        goto exit_slot_map;
    }

    io_uring->count = 0;

    return io_uring;

exit_slot_map:
    free(slot_map);
    free(io_uring);
    return NULL;
}

void *_run(void * data){
    IoUring *uring = (IoUring *)data;

    struct epoll_event events[16];
    while(true){
        int epoll_result = epoll_wait(uring->epollfd, events, sizeof(events)/sizeof(struct epoll_event), -1);
        if(epoll_result == -1){
            if(errno == EINTR){
                LOG_INFO("Program stop signal received");
            }
            else{
                ERRNO_ERROR("Wait failed");
            }
            return NULL;
        }else if(epoll_result == 0){
            ERROR("What?\n");
            continue;
        }

        for(size_t i = 0; i < epoll_result; i++){
            struct epoll_event event = events[i];
            if(event.data.fd == uring->stopfd){
                LOG_INFO("Stop signal received");
                uint64_t buff = 0;
                read(uring->stopfd, &buff, sizeof(buff));
                LOG_INFO("Stopping");
                return NULL;
            }
            else if(event.data.fd == uring->eventfd){
                uint64_t dummy;
                read(uring->eventfd, &dummy, sizeof(dummy));

                uint64_t result;
                while(_read_from_cq(uring, &result)){
                    size_t count = atomic_fetch_sub(&uring->count, 1) - 1;
                    SlotMapHandle handle;
                    memcpy(&handle, &result, sizeof(handle));
                    LOG_DEBUG("Uring dequeued item (index: %d, rev: %d). %zu items in flight.", handle.index, handle.revision, count);
                    IoUringCallback callback;
                    if(slot_map_try_get(uring->slot_map, handle, &callback)){
                        callback.invoke(callback.u_data);
                        slot_map_remove(uring->slot_map, handle);
                    }
                    else{
                        ERROR("Invalid handle, index %d, revision %d", handle.index, handle.revision);
                    }
                }
            }
            else{
                assert(false && "What?");
            }
        }
    }
}

static bool _read_from_cq(IoUring *uring, uint64_t *result){
    unsigned int head = io_uring_smp_load_acquire(uring->ring.completion_ring.head);
    if(head == *uring->ring.completion_ring.tail){
        return false;
    }

    bool success = true;
    struct io_uring_cqe *event = &uring->ring.completion_ring.entries[head & *uring->ring.completion_ring.mask];
    if(event->res < 0){
        printf("Penis\n");
        success = false;
    }
    else{
        *result = event->user_data;
    }

    head++;
    io_uring_smp_store_release(uring->ring.completion_ring.head, head);

    return success;
}

bool io_uring_submit(IoUring *uring, IoUringOp op, IoUringCallback cb){
    assert(sizeof(SlotMapHandle) == 8);
    SlotMapHandle handle;
    if(!slot_map_try_add(uring->slot_map, &cb, &handle)){
        return false;
    }

    pthread_mutex_lock(&uring->lock);
    unsigned int tail = *uring->ring.subbmission_ring.tail;
    unsigned int index = tail & *uring->ring.subbmission_ring.mask;

    struct io_uring_sqe *entry = &uring->ring.subbmission_ring.entries[index];
    entry->opcode = op.op;
    entry->fd = op.fd;
    entry->addr = (uint64_t) op.buff;
    entry->len = op.length;
    mempcpy(&entry->user_data, &handle, 8);

    uring->ring.subbmission_ring.array[index] = index;
    tail++;

    io_uring_smp_store_release(uring->ring.subbmission_ring.tail, tail);

    size_t count = atomic_fetch_add(&uring->count, 1) + 1;
    LOG_DEBUG("Uring is enqueueing item number %zu (index: %d, rev: %d)", count, handle.index, handle.revision);
#ifdef USE_POLLING
    int result = 1;
    unsigned flags = atomic_load_explicit((atomic_uint *)uring->ring.subbmission_ring.flags, memory_order_relaxed);
    if (flags & IORING_SQ_NEED_WAKEUP){
        result = io_uring_enter(uring->ring.uring_fd, 0, 0, IORING_ENTER_SQ_WAKEUP);
    }
#else
    int result = io_uring_enter(uring->ring.uring_fd, 1, 0, 0);
#endif
    LOG_DEBUG("Item enqueued");
    pthread_mutex_unlock(&uring->lock);
    if(result < 0){
        perror("Enter ):");
        return false;
    }

    return true;
}
