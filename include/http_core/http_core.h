#ifndef HTTP_CORE_H
#define HTTP_CORE_H

#include "buffers.h"
#include "http_message.h"
#include "task/task.h"
#include "threadpool/cancellation_token.h"

typedef struct{
    void (*invoke)(void *u_data, HttpResponse *response);
    void *u_data;
}ResponseCallback;

bool http_core_init(const char *content_path);
void http_core_free();
void http_core_create_response(const HttpRequest *request, HttpResponse *response, Buffer *buffer);
Task http_core_create_response_async(const HttpRequest *request, ResponseCallback callback, CancellationToken *token);

#endif
