#ifndef HTTP_H
#define HTTP_H

#include "server_worker.h"

typedef struct Http2Ctx Http2Ctx;

Http2Ctx *http2_new_ctx(ServerWorker *worker);
void http2_free_ctx(Http2Ctx *ctx);

void http2_handle_message(Http2Ctx *ctx, void *user_data, const ClientHandle client, char *buff, size_t len);
void http2_handle_connect(Http2Ctx *ctx, const ClientHandle client);
void http2_handle_disconnect(Http2Ctx *ctx, void *u_client_data, const ClientHandle client);

#endif
