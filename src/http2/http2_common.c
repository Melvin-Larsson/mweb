#include "http2_common.h"
#include "http_core/http_core.h"
#include "http2_logging.h"

bool http2_common_send(Http2Client *client, uint8_t *data, size_t size){
    return client->send_cb.send(client->send_cb.u_data, data, size);
}

void http2_common_send_goaway(Http2Client *client, ErrorCode error_code){
    InternalGoAwayFrame goaway = http2_frame_create_goaway_frame(client->highest_processed_stream_id, error_code);
    uint8_t buffer[512];
    size_t size = http2_frame_serialize_goaway_frame((char *)buffer, sizeof(buffer), &goaway);
    http2_common_send(client, buffer, size);
    //TODO close connection
}

void http2_common_handle_headers(Http2Client *client, Stream *stream, InternalHeaderFrame frame){
    uint8_t data[4096];
    Buffer buffer;
    ParseBuffer header_parse_buffer;
    buffers_init_buffer(&buffer, data, sizeof(data));
    buffers_init_parse_buffer(&header_parse_buffer, (uint8_t *)frame.header_block_fragment, frame.header_block_size);

    assert(frame.header.flags & END_HEADERS);

    HttpHeaderField headers[32];
    size_t header_count = 0;

    printf("body: \n");
    for(size_t i = 0; i < 8; i++){
        printf("%X ", (uint8_t)frame.header_block_fragment[i]);
    }
    printf("\n");

    HpackStatus status = hpack_decode_headers(client->decoder, &header_parse_buffer, headers, sizeof(headers) / sizeof(HttpHeaderField), &header_count, &buffer);
    if(status != HpackStatusOk){
        ERROR("Failed to parse headers, reason %d", status);
    }
    else if(buffer.used_size >= buffer.total_size){
        ERROR("Message headers too big for buffer, used %zu/%zu", buffer.used_size, buffer.total_size);
    }
    printf("Found %zu headers\n", header_count);
    for(size_t i = 0; i < header_count; i++){
        HttpHeaderField header = headers[i];
        for(size_t i = 0; i < header.name_length; i++){
            printf("%c", header.name[i]);
        }
        printf(": ");
        for(size_t i = 0; i < header.value_length; i++){
            printf("%c", header.value[i]);
        }
        printf("\n");
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
        return;
    }

    if(!has_path){
        ERROR("Request is missing path");
        return;
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
    http_core_create_response(&request, &http_response, &response_buffer);

    printf("Created response:\n%.*s\n", (int)http_response.body_size, (char *)http_response.body);
    printf("With header fields\n");
    http_header_fields_print(http_response.headers, http_response.header_count);

    uint8_t *response_headers = buffer_get_append_ptr(&buffer);
    HttpHeaderField status_header_field = http_status_header_field(http_response.status);
    size_t header_size = hpack_encode_headers(client->encoder, &status_header_field, 1, &buffer, IndexTypeIncremental);
    header_size += hpack_encode_headers(client->encoder, http_response.headers, http_response.header_count, &buffer, IndexTypeIncremental);
    assert(!buffer_size_is_full(&buffer));

    InternalHeaderFrame header_frame = http2_frame_create_header_frame(response_headers, header_size, frame.header.stream_id, true);
    InternalDataFrame data_frame = http2_frame_create_data_frame(http_response.body, http_response.body_size, frame.header.stream_id);
    data_frame.header.flags |= END_STREAM;
    if(http_response.body_size == 0){
        header_frame.header.flags |= END_STREAM;
    }

    uint8_t *frame_ptr = buffer_get_append_ptr(&buffer);
    size_t total_size = 0;
    size_t size_left = buffer_size_left(&buffer);
    size_t headers_size = http2_frame_serialize_header_frame((char *)frame_ptr, size_left, &header_frame);
    size_left -= headers_size;
    total_size += headers_size;
    if(http_response.body_size > 0){
        size_t data_size = http2_frame_serialize_data_frame((char *)frame_ptr + headers_size, size_left, &data_frame);
        size_left -= data_size;
        total_size += data_size;
    }

    assert(size_left != 0);

    LOG_DEBUG("Sending %zu bytes to client", total_size);
    http2_common_send(client, frame_ptr, total_size);

    stream->state = Closed;
}

