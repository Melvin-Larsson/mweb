#ifndef HTTP_H
#define HTTP_H

#include "task/task.h"
#include "threadpool/cancellation_token.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct Http2Client Http2Client;

typedef struct{
    bool (*send)(void *u_data, const uint8_t *data, size_t size);
    void *u_data;
}Http2SendCb;

Http2Client *http2_client_new(Http2SendCb send_cb);
void http2_client_free(Http2Client *client);

TaskList http2_client_handle_message_async(Http2Client *client, const char *buff, size_t len, CancellationToken *token);

#endif
