#ifndef HTTP_H
#define HTTP_H

#include "server_worker.h"
void http2_handle_message(void *data, const ClientHandle client, char *buff, size_t len);

#endif
