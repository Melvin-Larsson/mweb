#ifndef HTTP_CORE_H
#define HTTP_CORE_H

#include "http2/buffers.h"
#include "http_core/http_message.h"

bool http_core_init(const char *content_path);
void http_core_create_response(const HttpRequest *request, HttpResponse *response, Buffer *buffer);

#endif
