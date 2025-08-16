#include "http2/http2.h"
#include <string.h>
#include "http2/hpack.h"
#include "http_core/http_core.h"
#include "inttypes.h"
#include "stdio.h"
#include "stdlib.h"
#include "assert.h"

#include "http2_frame.h"
#include "http2_logging.h"


#define min(x, y) ((x) < (y) ? (x) : (y))

#define PRIORITY_DATA_LENGTH 5
#define DEFAULT_WINDOW_SIZE 65535
#define MAX_STREAMS_PER_CLIENT 32

typedef enum{
    ConnectionPreface,
    Running
}ClientStatus;

typedef enum{
    Ok,
    InvaidConnectionPreface,
}Http2InternalStatus;

typedef enum{
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
    Closed
}StreamState;

typedef struct{
    size_t id;
    StreamState state;
    size_t window_size;
}Stream;

typedef struct{
    ClientStatus status;
    uint32_t highest_client_stream_id;
    Stream streams[MAX_STREAMS_PER_CLIENT];
    ClientHandle handle;
    HpackEncoder *encoder;
    HpackDecoder *decoder;
    size_t window_size;
}Client;

struct Http2Ctx{
    ServerWorker *worker;
};

static void _print_settings(InternalSettingsFrame *settings);

static ParseStatus _parse_priority_data(char *buff, size_t len, InternalPriorityData *result);

static FrameType _get_frame_type(char *buff, size_t len);
static size_t _to_external_frame(InternalFrameHeader frame, char *buffer, size_t buffer_size);

static bool _ignore_frame(ParseBuffer *buffer);

void default_stream_handle_message(Http2Ctx *ctx, Client *client, ParseBuffer *parse_buffer);
void default_stream_handle_settings(Http2Ctx *ctx, Client *client, InternalSettingsFrame frame);
void default_stream_handle_window_update(Http2Ctx *ctx, Client *client, InternalWindowUpdateFrame frame);

void idle_stream_handle_message(Http2Ctx *ctx, Client *client, Stream *stream, ParseBuffer *parse_buffer);
void idle_stream_handle_headers(Http2Ctx *ctx, Client *client, Stream *stream, InternalHeaderFrame frame);

void open_stream_handle_message(Http2Ctx *ctx, Client *client, Stream *stream, ParseBuffer *parse_buffer);
void open_stream_handle_data(Http2Ctx *ctx, Client *client, Stream *stream, InternalDataFrame frame);
void open_stream_handle_headers(Http2Ctx *ctx, Client *client, Stream *stream, InternalHeaderFrame frame);
void open_stream_handle_goaway(Http2Ctx *ctx, Client *client, Stream *stream, InternalGoAwayFrame frame);
void open_stream_handle_window_update(Http2Ctx *ctx, Client *client, Stream *stream, InternalWindowUpdateFrame frame);
void open_stream_handle_continuation(Http2Ctx *ctx, Client *client, Stream *stream, InternalContinuationFrame frame);

Http2Ctx *http2_new_ctx(ServerWorker *worker){
    Http2Ctx *ctx = malloc(sizeof(Http2Ctx));
    if(ctx == NULL){
        return NULL;
    }
    *ctx = (Http2Ctx){
        .worker = worker
    };

    return ctx;
}

void http2_free_ctx(Http2Ctx *ctx){
    free(ctx);
}

void http2_handle_connect(Http2Ctx *ctx, const ClientHandle handle){
    LOG_INFO("Client connected, id %d, generation %d\n", handle.index, handle.generation);
    Client *client = malloc(sizeof(Client));
    assert(client != NULL);
 
    *client = (Client){
        .status = ConnectionPreface,
        .decoder = hpack_decoder_new(4096),
        .encoder = hpack_encoder_new(4096),
        .highest_client_stream_id = 0,
        .streams = {0},
        .window_size = DEFAULT_WINDOW_SIZE,
        .handle = handle
    };
 
    assert(client->decoder != NULL);
    assert(client->encoder != NULL);
 
    server_worker_attach_client_data(ctx->worker, handle, client);
}

void http2_handle_disconnect(Http2Ctx *ctx, void *u_client_data, const ClientHandle handle){
    LOG_INFO("Client disconnected\n");
    Client *client = u_client_data;
    if(client == NULL){
        return;
    }

    hpack_decoder_free(client->decoder);
    hpack_encoder_free(client->encoder);
    free(client);
}

Http2InternalStatus _connection_preface_message(Http2Ctx *ctx, Client *client, ParseBuffer *buffer){
    char *connect_string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    size_t size_left = buffer->total_size - buffer->parsed_size;
    if(size_left >= strlen(connect_string) && strncmp((char *)&buffer->data[buffer->parsed_size], connect_string, strlen(connect_string)) == 0){
        buffer->parsed_size += strlen(connect_string);
        return Ok;
    }    

    return InvaidConnectionPreface;
}

void http2_handle_message(Http2Ctx *ctx, void *user_data, const ClientHandle handle, char *buff, size_t len){
    Client *client = (Client *)user_data;
    if(client == NULL){
        ERROR("Client is null");
        return;
    }

    printf("Handling http2\n");
    for(size_t i = 0; i < len; i++){
        printf("%02X ", (unsigned char)buff[i]);
    }
    printf("\n");

    for(size_t i = 0; i < len; i++){
        if(buff[i] < 128 && buff[i] >= 20)
            printf("%c  ", (unsigned char)buff[i]);
        else if(buff[i] == '\n')
            printf("\\n ");
        else if(buff[i] == '\r')
            printf("\\r ");
        else
            printf("?  ");
    }
    printf("\n");

    ParseBuffer parse_buffer;
    buffers_init_parse_buffer(&parse_buffer, (uint8_t *)buff, len);

    if(client->status == ConnectionPreface){
        LOG_INFO("Connection preface of size %zu", parse_buffer.total_size - parse_buffer.parsed_size);
        Http2InternalStatus status = _connection_preface_message(ctx, client, &parse_buffer);
        if(status != Ok){
            ERROR("Connection preface failed\n");
            exit(EXIT_FAILURE);
        }
        client->status = Running;
        LOG_INFO("Connection preface done with %zu bytes left\n", parse_buffer.total_size - parse_buffer.parsed_size);
    }

    uint8_t buffer[4096];

    while(parse_buffer.parsed_size < parse_buffer.total_size){
        size_t initial_parsed_size = parse_buffer.parsed_size;
        LOG_DEBUG("Parsing frame of size %zu", parse_buffer.total_size - parse_buffer.parsed_size);
        for(size_t i = 0; i < min(parse_buffer.total_size - parse_buffer.parsed_size, 32); i++){
            printf("0x%X ", parse_buffer.data[parse_buffer.parsed_size + i]);
        }
        printf("\n");

        uint32_t stream_id;
        if(!http2_frame_try_get_stream_id((char *)&parse_buffer.data[parse_buffer.parsed_size], parse_buffer.total_size - parse_buffer.parsed_size, &stream_id)){
            ERROR("Unable to get stream id from message");
            return;
        }
        printf("%u\n", stream_id);
        LOG_DEBUG("Message has stream id %u\n", stream_id);

        if(stream_id == 0){
            default_stream_handle_message(ctx, client, &parse_buffer);
            continue;
        }

        Stream *stream = NULL;
        for(size_t i = 0; i < MAX_STREAMS_PER_CLIENT; i++){
            if(client->streams[i].id == stream_id){
                stream = &client->streams[i];
                break;
            }
        }
        if(stream == NULL){
            if(stream_id <= client->highest_client_stream_id){
                if(!_ignore_frame(&parse_buffer)){
                    ERROR("Not enough stuff in buffer");
                    exit(EXIT_FAILURE);
                }
                continue;
            }
            else{
                for(size_t i = 0; i < MAX_STREAMS_PER_CLIENT; i++){
                    if(client->streams[i].id == 0){
                        stream = &client->streams[i];
                        *stream = (Stream){
                            .id = stream_id,
                            .state = Idle,
                            .window_size = DEFAULT_WINDOW_SIZE
                        };
                        client->highest_client_stream_id = stream_id;
                        break;
                    }
                }
            }
        }
        if(stream == NULL){
            ERROR("Unable to find free stream");
            return;
        }

        switch(stream->state){
            case Idle:
                LOG_DEBUG("Handling message for idle stream %d", stream_id);
                idle_stream_handle_message(ctx, client, stream, &parse_buffer);
                break;
            case Open:
                LOG_DEBUG("Handling message for open stream %d", stream_id);
                open_stream_handle_message(ctx, client, stream, &parse_buffer);
                break;
            default:
                ERROR("Unable to handle stream in state %d", stream->state);
                exit(EXIT_FAILURE);
                return;
        }

        LOG_DEBUG("parsed %zu, total %zu", parse_buffer.parsed_size, parse_buffer.total_size);

        if(parse_buffer.parsed_size == initial_parsed_size){
            ERROR("Unable to handle message");
            exit(EXIT_FAILURE);
            return;
        }
    }
    LOG_INFO("============== Message handled");
}

static bool _ignore_frame(ParseBuffer *buffer){
    size_t payload_size;
    if(!http2_frame_try_get_length(&buffer->data[buffer->parsed_size], buffer->total_size - buffer->parsed_size, &payload_size)){
        return false;
    }
    size_t frame_size = 9 + payload_size;
    LOG_DEBUG("Ignoring frame of size %zu", frame_size);
    if(buffer->total_size - buffer->parsed_size < frame_size){
        return false;
    }

    buffer->parsed_size += frame_size;
    return true;
}

void default_stream_handle_message(Http2Ctx *ctx, Client *client, ParseBuffer *parse_buffer){
    FrameType type = http2_frame_get_frame_type((char *)&parse_buffer->data[parse_buffer->parsed_size], parse_buffer->total_size - parse_buffer->parsed_size);
    if(type == Invalid){
        LOG_DEBUG("Invalid frame type %d\n", type);
        return;
    }

    switch(type){
        case Settings:
            {
                LOG_INFO("Received settings frame on default stream");
                InternalSettingsFrame settings;
                ParseStatus status = http2_frame_parse_settings_frame(parse_buffer, &settings);
                if(status != ParseStatusSuccess){
                    LOG_DEBUG("Failed to parse settings frame. Reason %d", status);
                    return;
                }
                default_stream_handle_settings(ctx, client, settings);
            }
            break;
        case WindowUpdate:
            {
                InternalWindowUpdateFrame window_frame;
                ParseStatus status = http2_frame_parse_window_update_frame(parse_buffer, &window_frame);
                if(status != ParseStatusSuccess){
                    ERROR("Failed to parse window update frame");
                    return;
                }
                default_stream_handle_window_update(ctx, client, window_frame);
                return;
            }
        case GoAway:
            {
                InternalGoAwayFrame go_away_frame;
                ParseStatus status = http2_frame_parse_goaway_frame(parse_buffer, &go_away_frame);
                if(status != ParseStatusSuccess){
                    ERROR("Failed to parse go away frame");
                    return;
                }
                LOG_DEBUG("Go away received, reason %d", go_away_frame.error_code);
                return;
            }
            return;
        default:
            ERROR("Unable to handle frame of type %d on default stream", type);
            exit(EXIT_FAILURE);
            break;
    }

}

void default_stream_handle_settings(Http2Ctx *ctx, Client *client, InternalSettingsFrame frame){
    if(frame.header.flags & ACK){
        LOG_DEBUG("Settings acked");
        return;
    }

    uint8_t buffer[4096];
    http2_frame_print_settings(&frame);

    LOG_DEBUG("Sending empty settings frame...");
    InternalSettingsFrame server_settings_frame = http2_frame_create_empty_settings_frame();
    size_t server_settings_frame_size = http2_frame_serialize_settings_frame((char *)buffer, sizeof(buffer), &server_settings_frame);
    assert(server_settings_frame_size < sizeof(buffer));
    server_worker_send(ctx->worker, client->handle, (char *)buffer, server_settings_frame_size);

    LOG_DEBUG("Sending ack frame...");
    InternalSettingsFrame ack_frame = http2_frame_create_ack_settings_frame();
    size_t ack_frame_size =  http2_frame_serialize_settings_frame((char *)buffer, sizeof(buffer), &ack_frame);
    assert(ack_frame_size < sizeof(buffer));
    server_worker_send(ctx->worker, client->handle, (char *)buffer, ack_frame_size);

}

void default_stream_handle_window_update(Http2Ctx *ctx, Client *client, InternalWindowUpdateFrame frame){
}

void idle_stream_handle_message(Http2Ctx *ctx, Client *client, Stream *stream, ParseBuffer *parse_buffer){
    assert(stream->state == Idle);
    FrameType type = http2_frame_get_frame_type((char *)&parse_buffer->data[parse_buffer->parsed_size], parse_buffer->total_size - parse_buffer->parsed_size);
    if(type == Invalid){
        LOG_DEBUG("Invalid frame type %d\n", type);
        return;
    }

    switch(type){
        case Headers:
            {
                InternalHeaderFrame header;
                ParseStatus status = http2_frame_parse_header_frame(parse_buffer, &header);
                if(status != ParseStatusSuccess){
                    ERROR("Failed to parse header frame");
                    return;
                }
                idle_stream_handle_headers(ctx, client, stream, header);
                stream->state = Open;
                return;
            }
        case Priority:
            LOG_DEBUG("Prioirity requests are not implemented");
            return;
        default:
            ERROR("Faulty message type %d in idle state", type);
            return;
    }
}

void _generic_stream_handle_headers(Http2Ctx *ctx, Client *client, Stream *stream, InternalHeaderFrame frame){
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

    char *frame_ptr = (char *)buffer_get_append_ptr(&buffer);
    size_t total_size = 0;
    size_t size_left = buffer_size_left(&buffer);
    size_t headers_size = http2_frame_serialize_header_frame(frame_ptr, size_left, &header_frame);
    size_left -= headers_size;
    total_size += headers_size;
    if(http_response.body_size > 0){
        size_t data_size = http2_frame_serialize_data_frame(frame_ptr + headers_size, size_left, &data_frame);
        size_left -= data_size;
        total_size += data_size;
    }

    assert(size_left != 0);

    LOG_DEBUG("Sending %zu bytes to client", total_size);
    ServerWorkerStatus send_status = server_worker_send(ctx->worker, client->handle, frame_ptr, total_size);
    printf("Send status %d to id %d revisoion %d\n", send_status, client->handle.index, client->handle.generation);

    stream->id = 0;
    stream->state = Closed;

//     printf("=========Dynamic Headers===========");
//     hpack_decoder_print_dynamic_headers(client->decoder);
//     printf("=========END===========");
}

void idle_stream_handle_headers(Http2Ctx *ctx, Client *client, Stream *stream, InternalHeaderFrame frame){
    assert(frame.header.type == Headers);
    _generic_stream_handle_headers(ctx, client, stream, frame);
}

void open_stream_handle_message(Http2Ctx *ctx, Client *client, Stream *stream, ParseBuffer *parse_buffer){
    FrameType type = http2_frame_get_frame_type((char *)&parse_buffer->data[parse_buffer->parsed_size], parse_buffer->total_size - parse_buffer->parsed_size);
    if(type == Invalid){
        LOG_DEBUG("Invalid frame type %d\n", type);
        return;
    }
    switch(type){
        case Headers:
            {
                InternalHeaderFrame header_frame;
                ParseStatus status = http2_frame_parse_header_frame(parse_buffer, &header_frame);
                if(status != ParseStatusSuccess){
                    ERROR("Failed to parse header frame");
                    return;
                }
                idle_stream_handle_headers(ctx, client, stream, header_frame);
                stream->state = Open;
                return;
            }
        case Data:
            {
                InternalDataFrame data_frame;
                ParseStatus status = http2_frame_parse_data_frame(parse_buffer, &data_frame);
                if(status != ParseStatusSuccess){
                    ERROR("Failed to parse data frame");
                    return;
                }
                open_stream_handle_data(ctx, client, stream, data_frame);
                return;
            }
        case GoAway:
            {
                InternalGoAwayFrame goaway_frame;
                ParseStatus status = http2_frame_parse_goaway_frame(parse_buffer, &goaway_frame);
                if(status != ParseStatusSuccess){
                    ERROR("Failed to parse go-away frame");
                    return;
                }
                open_stream_handle_goaway(ctx, client, stream, goaway_frame);
                return;
            }
        case WindowUpdate:
            {
                InternalWindowUpdateFrame window_frame;
                LOG_INFO("Before %zu", parse_buffer->parsed_size);
                ParseStatus status = http2_frame_parse_window_update_frame(parse_buffer, &window_frame);
                LOG_INFO("After %zu", parse_buffer->parsed_size);
                if(status != ParseStatusSuccess){
                    ERROR("Failed to parse window update frame");
                    return;
                }
                open_stream_handle_window_update(ctx, client, stream, window_frame);
                return;
            }
        case Continuation:
            {
                InternalContinuationFrame continuation_frame;
                ParseStatus status = http2_frame_parse_continuation_frame(parse_buffer, &continuation_frame);
                if(status != ParseStatusSuccess){
                    ERROR("Failed to parse continuation frame");
                    return;
                }
                open_stream_handle_continuation(ctx, client, stream, continuation_frame);
                return;
            }
        case Priority:
            LOG_DEBUG("Prioirity requests are not implemented");
            return;
        default:
            ERROR("Invalid message type %d received on open stream", type);
    }
}

void open_stream_handle_headers(Http2Ctx *ctx, Client *client, Stream *stream, InternalHeaderFrame frame){
    assert(stream->state == Open);
    assert(frame.header.type == Headers);
    _generic_stream_handle_headers(ctx, client, stream, frame);

}

void open_stream_handle_data(Http2Ctx *ctx, Client *client, Stream *stream, InternalDataFrame frame){
    LOG_DEBUG("Handle data not implemented");
}
void open_stream_handle_goaway(Http2Ctx *ctx, Client *client, Stream *stream, InternalGoAwayFrame frame){
    LOG_DEBUG("Open stream goaway not implemented");

}
void open_stream_handle_window_update(Http2Ctx *ctx, Client *client, Stream *stream, InternalWindowUpdateFrame frame){
    assert(stream->state == Open);
    assert(frame.header.type == WindowUpdate);
    stream->window_size += frame.size_increment;
}

void open_stream_handle_continuation(Http2Ctx *ctx, Client *client, Stream *stream, InternalContinuationFrame frame){
    LOG_DEBUG("Open stream continuation not implemented");
}

// static size_t _to_external_frame(InternalFrame frame, char *buffer, size_t buffer_size){
//     ExternalFrameHeader header = {
//         .length = _reverse_byte_order_24(frame.length),
//         .flags = frame.flags,
//         .type = frame.type,
//         .stream_id = frame.stream_id,
//     };
//     size_t header_copy_size = min(sizeof(ExternalFrameHeader), buffer_size);
//     memcpy(buffer, &header, header_copy_size);
//     if(header_copy_size >= buffer_size){
//         return header_copy_size;
//     }

//     size_t body_copy_size = min(buffer_size - header_copy_size, frame.length);
//     memcpy(buffer + header_copy_size, frame.payload, body_copy_size);

//     return header_copy_size + body_copy_size;
// }
