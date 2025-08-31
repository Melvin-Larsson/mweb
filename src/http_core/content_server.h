#ifndef CONTENT_SERVER_H
#define CONTENT_SERVER_H

#include <stddef.h>

typedef enum{
    ContentServerOk,
    ContentServerInvalidTag,
    ContentServerUnableToStartServer
}ContentServerStatus;

typedef struct ContentServer ContentServer;

ContentServer *content_server_new();
ContentServerStatus content_server_get_content(ContentServer *server, const char *tag, char **result, size_t *result_length);

#endif
