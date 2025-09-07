#ifndef CONTENT_SERVER_H
#define CONTENT_SERVER_H

#include "task/task.h"
#include "threadpool/cancellation_token.h"
#include <stddef.h>

typedef enum{
    ContentServerOk,
    ContentServerInvalidTag,
    ContentServerUnableToStartServer,
    ContentServerUnableToEpoll,
    ContentServerOutOfMemory,
    ContentServerDeserializeFailure
}ContentServerStatus;

typedef struct{
    size_t length;
    const char *tag;
}Tag;

typedef struct{
    size_t length;
    const char *content;
}Content;

typedef struct{
    ContentServerStatus status;
    const Content *content;
    size_t content_count;
}ContentResult;

typedef struct ContentServer ContentServer;

ContentServer *content_server_new();
ContentServerStatus content_server_run(ContentServer *server);
Task content_server_get_content_async(ContentServer *server, const Tag *tags, size_t tag_count, TaskList (*cb)(void *ctx, ContentResult content), void *ctx, CancellationToken *token);

#endif
