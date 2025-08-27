#include "http2_common.h"
#include "http_core/http_core.h"
#include <stdlib.h>

#define LOG_CONTEXT "Http2"
#include "logging.h"

static void _send_response_headers(Http2Client *client, Stream *stream, HttpResponse *response);
static void _free_response_ctx(void *args);

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

static TaskList _on_body_async(void *u_data, bool success, uint8_t *data, size_t size){
    ResponseCtx *ctx = (ResponseCtx *)u_data;
    Http2Client *client = ctx->client;
    Stream *stream = ctx->stream;

    cancellation_token_remove_callback(ctx->token, ctx->handle);

    if(!success){
        LOG_WARNING("Failed to ready body");
        http2_common_send_goaway(client, ErrorCodeNoError);
        http_core_partial_response_free(stream->response_handle);
        stream->response_handle = NULL;
        free(ctx);
        return task_list_empty();
    }

    if(size == 0){
        LOG_WARNING("Empty body received when creating resposne body");
        http_core_partial_response_free(stream->response_handle);
        stream->response_handle = NULL;
        free(ctx);
        return task_list_empty();
    }

    stream->window_size -= size;
    client->window_size -= size;

    bool is_last = !http_core_partial_response_has_more(stream->response_handle);

    TaskList result = task_list_empty();
    LOG_TRACE("Sending data frame of size %d", size);
    if(is_last){
        LOG_DEBUG("No more body data to read");
        http_core_partial_response_free(stream->response_handle);
        stream->response_handle = NULL;
        LOG_TRACE("Last frame");
        free(ctx);
        stream->state = Closed;
    }
    else{
        BodyResponseCallback callback = {
            .invoke = _on_body_async,
            .u_data = ctx,
        };
        size_t read_size = min(stream->window_size, client->window_size);
        if(read_size == 0){
            LOG_DEBUG("More body data to read, but send window has closed (stream: %d, connection %d)", stream->window_size, client->window_size);
            stream->waiting_for_send_window = true;
            free(ctx);
        }
        else{
            LOG_DEBUG("More body data to read, will read of size %d", read_size);

            CancellationTokenCallback cb = {
                .on_cancel = _free_response_ctx,
                .u_data = ctx
            };
            cancellation_token_add_callback(ctx->token, cb, &ctx->handle);
            Task task = http_core_advance_partial_response_async(stream->response_handle, read_size, callback, ctx->token);
            task_list_add_task(&result, task);
        }
    }

    //FIXME: We shouldn't allocate new buffer here
    size_t payload_size = min(size, client->max_frame_size);
    size_t buffer_size = payload_size + 1024;
    uint8_t *buffer = malloc(buffer_size);
    assert(buffer);
    while(size > 0){
        payload_size = min(size, client->max_frame_size);

        InternalDataFrame frame = http2_frame_create_data_frame(data, payload_size, stream->id);
        LOG_TRACE("Created frame for size %d/%d", payload_size, size);

        if(size == payload_size && is_last){
            frame.header.flags |= END_STREAM;
            LOG_DEBUG("Setting end stream flag");
        }

        size_t frame_size = http2_frame_serialize_data_frame((char *)buffer, buffer_size, &frame);
        assert(frame_size != buffer_size);

        http2_common_send(client, buffer, frame_size);

        data += payload_size;
        size -= payload_size;
    }

    free(buffer);

    return result;
}

static void _free_response_ctx(void *args){
    ResponseCtx *ctx = (ResponseCtx *)args;
    http_core_partial_response_free(ctx->stream->response_handle);
    ctx->stream->response_handle = NULL;
    free(ctx);
}

Task http2_common_advance_body(Http2Client *client, Stream *stream, CancellationToken *token){
    size_t read_size = min(stream->window_size, client->window_size);
    if(read_size == 0){
        LOG_TRACE("Unable to advance body, window is not open");
        return completed_task();
    }
    if(!stream->waiting_for_send_window){
        LOG_TRACE("Unable to advance body, stream is not waiting for send window");
        return completed_task();
    }
    ResponseCtx *ctx = malloc(sizeof(ResponseCtx));
    *ctx = (ResponseCtx){
        .client = client,
        .stream = stream,
        .token = token,
    };
    BodyResponseCallback callback = {
        .invoke = _on_body_async,
        .u_data = ctx,
    };

    LOG_DEBUG("Asking for resposne %X", ctx);
    CancellationTokenCallback cb = {
        .on_cancel = _free_response_ctx,
        .u_data = ctx
    };
    cancellation_token_add_callback(token, cb, &ctx->handle);

    LOG_TRACE("Advance partial read with %d bytes", read_size);
    stream->waiting_for_send_window = false;
    return http_core_advance_partial_response_async(stream->response_handle, read_size, callback, token);
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

    HttpResponse response;
    ResponseHandle *response_handle = http_core_new_partial_response(&request, &response);
    if(response_handle == NULL){
        http2_common_send_goaway(client, ErrorCodeNoError);
        return completed_task();
    }
    _send_response_headers(client, stream, &response);

    if(!http_core_partial_response_has_more(response_handle)){
        LOG_DEBUG("Response was completed on first request");
        http_core_partial_response_free(response_handle);
        stream->state = Closed;
        return completed_task();
    }

    stream->response_handle = response_handle;

    ResponseCtx *ctx = malloc(sizeof(ResponseCtx));
    *ctx = (ResponseCtx){
        .client = client,
        .stream = stream,
        .token = token,
    };
    BodyResponseCallback callback = {
        .invoke = _on_body_async,
        .u_data = ctx,
    };

    LOG_DEBUG("Asking for resposne %X", ctx);
    CancellationTokenCallback cb = {
        .on_cancel = _free_response_ctx,
        .u_data = ctx
    };
    cancellation_token_add_callback(token, cb, &ctx->handle);

    size_t read_size = min(stream->window_size, client->window_size);
    LOG_TRACE("Advance partial read with %d bytes (stream: %d, client %d)", read_size, stream->window_size, client->window_size);
    return http_core_advance_partial_response_async(response_handle, read_size, callback, token);
}

static void _send_response_headers(Http2Client *client, Stream *stream, HttpResponse *response){
#if LOG_LEVEL <= LOG_LEVEL_DEBUG
    http_header_fields_print(response->headers, response->header_count);
#endif

    uint8_t buffer_data[4096];
    Buffer buffer;
    buffers_init_buffer(&buffer, buffer_data, sizeof(buffer_data));

    uint8_t *response_headers = buffer_get_append_ptr(&buffer);
    HttpHeaderField status_header_field = http_status_header_field(response->status);
    size_t header_size = hpack_encode_headers(client->encoder, &status_header_field, 1, &buffer, IndexTypeIncremental);
    header_size += hpack_encode_headers(client->encoder, response->headers, response->header_count, &buffer, IndexTypeIncremental);
    assert(!buffer_size_is_full(&buffer));

    InternalHeaderFrame header_frame = http2_frame_create_header_frame(response_headers, header_size, stream->id, true);
    if(response->body_size == 0){
        header_frame.header.flags |= END_STREAM;
        LOG_TRACE("Last frame");
    }

    uint8_t *frame_ptr = buffer_get_append_ptr(&buffer);
    size_t headers_size = http2_frame_serialize_header_frame((char *)frame_ptr, buffer_size_left(&buffer), &header_frame);

    http2_common_send(client, frame_ptr, headers_size);
}
