#ifndef CONTENT_SERVER_H
#define CONTENT_SERVER_H

#include <stddef.h>

typedef enum{
    ContentServerOk,
    ContentServerInvalidTag,
    ContentServerUnableToStartServer,
    ContentServerOutOfMemory,
}ContentServerStatus;

typedef struct ContentServer ContentServer;

ContentServer *content_server_new();
ContentServerStatus content_server_get_content(ContentServer *server, const char *tag, size_t tag_length, char **result, size_t *result_length);

#endif
