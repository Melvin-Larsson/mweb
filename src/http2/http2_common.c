#include "http2_common.h"
#include "http_core/http_core.h"
#include <stdlib.h>

#define LOG_CONTEXT "Http2"
#include "logging.h"

bool http2_common_send(Http2Client *client, uint8_t *data, size_t size){
    return client->send_cb.send(client->send_cb.u_data, data, size);
}

void http2_common_send_goaway(Http2Client *client, ErrorCode error_code){
    ERROR("Sending goaway");
    InternalGoAwayFrame goaway = http2_frame_create_goaway_frame(client->highest_processed_stream_id, error_code);
    uint8_t buffer[512];
    size_t size = http2_frame_serialize_goaway_frame((char *)buffer, sizeof(buffer), &goaway);
    http2_common_send(client, buffer, size);
    //TODO close connection
}

typedef struct{
    Http2Client *client;
    Stream *stream;
    CancellationToken *token;
    CancellationTokenCallbackHandle handle;
}ResponseCtx;

static void _on_response_created(void *u_data, HttpResponse *response){
    ResponseCtx *ctx = (ResponseCtx *)u_data;
    Http2Client *client = ctx->client;
    Stream *stream = ctx->stream;

    cancellation_token_remove_callback(ctx->token, ctx->handle);

    LOG_INFO("Created response:\n%.*s", (int)response->body_size, (char *)response->body);
    LOG_INFO("With header fields");
    http_header_fields_print(response->headers, response->header_count);

    uint8_t buffer_data[4096];
    Buffer buffer;
    buffers_init_buffer(&buffer, buffer_data, sizeof(buffer_data));

    uint8_t *response_headers = buffer_get_append_ptr(&buffer);
    HttpHeaderField status_header_field = http_status_header_field(response->status);
    size_t header_size = hpack_encode_headers(client->encoder, &status_header_field, 1, &buffer, IndexTypeIncremental);
    header_size += hpack_encode_headers(client->encoder, response->headers, response->header_count, &buffer, IndexTypeIncremental);
    assert(!buffer_size_is_full(&buffer));

    InternalHeaderFrame header_frame = http2_frame_create_header_frame(response_headers, header_size, stream->id, true);
    InternalDataFrame data_frame = http2_frame_create_data_frame(response->body, response->body_size, stream->id);
    data_frame.header.flags |= END_STREAM;
    if(response->body_size == 0){
        header_frame.header.flags |= END_STREAM;
    }

    uint8_t *frame_ptr = buffer_get_append_ptr(&buffer);
    size_t total_size = 0;
    size_t size_left = buffer_size_left(&buffer);
    size_t headers_size = http2_frame_serialize_header_frame((char *)frame_ptr, size_left, &header_frame);
    size_left -= headers_size;
    total_size += headers_size;
    if(response->body_size > 0){
        size_t data_size = http2_frame_serialize_data_frame((char *)frame_ptr + headers_size, size_left, &data_frame);
        size_left -= data_size;
        total_size += data_size;
    }

    assert(size_left != 0);

    LOG_DEBUG("Sending %zu bytes to client", total_size);
    http2_common_send(client, frame_ptr, total_size);

    stream->state = Closed;

    free(ctx);
}

static void _free_response_ctx(void *ctx){
    free(ctx);
}

Task http2_common_handle_headers_async(Http2Client *client, Stream *stream, InternalHeaderFrame frame, CancellationToken *token){
    uint8_t data[4096];
    Buffer buffer;
    ParseBuffer header_parse_buffer;
    buffers_init_buffer(&buffer, data, sizeof(data));
    buffers_init_parse_buffer(&header_parse_buffer, (uint8_t *)frame.header_block_fragment, frame.header_block_size);

    assert(frame.header.flags & END_HEADERS);

    HttpHeaderField headers[32];
    size_t header_count = 0;

    HpackStatus status = hpack_decode_headers(client->decoder, &header_parse_buffer, headers, sizeof(headers) / sizeof(HttpHeaderField), &header_count, &buffer);
    if(status != HpackStatusOk){
        ERROR("Failed to parse headers, reason %d", status);
    }
    else if(buffer.used_size >= buffer.total_size){
        ERROR("Message headers too big for buffer, used %zu/%zu", buffer.used_size, buffer.total_size);
    }

    bool has_method = false;
    bool has_path = false;
    Method method;
    const char *path;
    size_t path_length;
    const char *method_name = ":method";
    const char *path_name = ":path";

    for(size_t i = 0; i < header_count; i++){
        HttpHeaderField header = headers[i];

        if(strncmp(header.name, ":method", header.name_length) == 0){
            has_path = true;
            if(strncmp(header.value, "GET", header.value_length) == 0){
                method = GET;
            }
            else if(strncmp(header.value, "POST", header.value_length) == 0){
                method = POST;
            }
            else if(strncmp(header.value, "PUT", header.value_length) == 0){
                method = PUT;
            }
            else if(strncmp(header.value, "DELETE", header.value_length) == 0){
                method = DELETE;
            }
            else{
                ERROR("Request is missing valid method");
                has_path = false;
            }
        }

        if(strncmp(header.name, ":path", header.name_length) == 0){
            path = header.value;
            path_length = header.value_length;
            has_method = true;
        }   
    }

    if(!has_method){
        ERROR("Request is missing method");
        return completed_task();
    }

    if(!has_path){
        ERROR("Request is missing path");
        return completed_task();
    }

    HttpRequest request = {
        .method = method,
        .path = path,
        .path_length = path_length,
        .headers = headers,
        .header_count = header_count,

        .body = NULL,
        .body_size = 0,
    };

    uint8_t response_data[4096];
    Buffer response_buffer;
    buffers_init_buffer(&response_buffer, response_data, sizeof(response_data));
    HttpResponse http_response;

    ResponseCtx *ctx = malloc(sizeof(ResponseCtx));
    *ctx = (ResponseCtx){
        .client = client,
        .stream = stream,
        .token = token,
    };
    ResponseCallback callback = {
        .invoke = _on_response_created,
        .u_data = ctx,
    };

    LOG_DEBUG("Asking for resposne %X", ctx);
    CancellationTokenCallback cb = {
        .on_cancel = _free_response_ctx,
        .u_data = ctx
    };
    cancellation_token_add_callback(token, cb, &ctx->handle);
    return http_core_create_response_async(&request, callback, token);
}

