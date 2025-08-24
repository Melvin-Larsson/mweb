#ifndef IO_URING_H
#define IO_URING_H

#include <linux/io_uring.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct{
    void (*invoke)(void *u_data, uint8_t *data, size_t length);
    void *u_data;
}OnReadCallback;

typedef struct{
    void (*invoke)(void *data);
    void *u_data;
}IoUringCallback;

typedef struct{
    int fd;
    int op;
    void *buff;
    size_t length;
}IoUringOp;

typedef struct IoUring IoUring;

IoUring *io_uring_new();
bool io_uring_submit(IoUring *uring, IoUringOp op, IoUringCallback cb);

static inline IoUringOp io_uring_read_op(int fd, void *buff, size_t length){
    return (IoUringOp){
        .fd = fd,
        .op = IORING_OP_READ,
        .buff = buff,
        .length = length,
    };
}

#endif
