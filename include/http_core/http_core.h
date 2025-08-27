#ifndef HTTP_CORE_H
#define HTTP_CORE_H

#include "buffers.h"
#include "http_message.h"
#include "task/task.h"
#include "threadpool/cancellation_token.h"

typedef struct{
    TaskList (*invoke)(void *u_data, HttpResponse *response);
    void *u_data;
}ResponseCallback;

typedef struct{
    TaskList (*invoke)(void *u_data, bool success, uint8_t *data, size_t len);
    void *u_data;
}BodyResponseCallback;

typedef struct ResponseHandle ResponseHandle;

bool http_core_init(const char *content_path);
void http_core_free();
void http_core_create_response(const HttpRequest *request, HttpResponse *response, Buffer *buffer);

Task http_core_create_response_async(const HttpRequest *request, ResponseCallback callback, CancellationToken *token);

ResponseHandle *http_core_new_partial_response(const HttpRequest *request, HttpResponse *initial_response);
Task http_core_advance_partial_response_async(ResponseHandle *handle, size_t size, BodyResponseCallback callback, CancellationToken *token);
void http_core_partial_response_free(ResponseHandle *handle);
bool http_core_partial_response_has_more(ResponseHandle *handle);

#endif
