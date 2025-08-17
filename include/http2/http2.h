#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct Http2Client Http2Client;

typedef struct{
    bool (*send)(void *u_data, const uint8_t *data, size_t size);
    void *u_data;
}Http2SendCb;

Http2Client *http2_client_new(Http2SendCb cb);
void http2_client_free(Http2Client *client);

void http2_client_handle_message(Http2Client *client, const char *buff, size_t len);

#endif
