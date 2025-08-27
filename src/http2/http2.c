#include "http2/http2.h"
#include "http2_common.h"
#include <string.h>
#include "hpack.h"
#include "stream/stream.h"
#include "inttypes.h"
#include "stdio.h"
#include "stdlib.h"
#include "assert.h"
#include "http2_frame.h"

#define LOG_CONTEXT "Http2"
#include "logging.h"

static void _print_settings(InternalSettingsFrame *settings);
static ParseStatus _parse_priority_data(char *buff, size_t len, InternalPriorityData *result);
static FrameType _get_frame_type(char *buff, size_t len);
static size_t _to_external_frame(InternalFrameHeader frame, char *buffer, size_t buffer_size);
static bool _ignore_frame(ParseBuffer *buffer);
static bool _send(Http2Client *client, uint8_t *data, size_t size);

Http2Client *http2_client_new(Http2SendCb send_cb){
    assert(send_cb.send != NULL);

    Http2Client *client = malloc(sizeof(Http2Client));
    if(client == NULL){
        return NULL;
    }
    *client = (Http2Client){
        .status = ConnectionPreface,
        .decoder = hpack_decoder_new(4096),
        .encoder = hpack_encoder_new(4096),
        .highest_client_stream_id = 0,
        .streams = {0},
        .window_size = DEFAULT_WINDOW_SIZE,
        .send_cb = send_cb,
        .initial_window_size = DEFAULT_WINDOW_SIZE,
        .max_frame_size = DEFAULT_MAX_FRAME_SIZE,
    };

    if(client->decoder == NULL || client->encoder == NULL){
        free(client);
        hpack_decoder_free(client->decoder);
        hpack_encoder_free(client->encoder);
        return NULL;
    }

    return client;
}

void http2_client_free(Http2Client *client){
    if(client == NULL){
        return;
    }

    hpack_decoder_free(client->decoder);
    hpack_encoder_free(client->encoder);
    for(size_t i = 0; i < MAX_STREAMS_PER_CLIENT; i++){
        http_core_partial_response_free(client->streams[i].response_handle);
        client->streams[i].response_handle = NULL;
    }
    free(client);
}

Http2InternalStatus _connection_preface_message(Http2Client *client, ParseBuffer *buffer){
    char *connect_string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    size_t size_left = buffer->total_size - buffer->parsed_size;
    uint8_t *data = &buffer->data[buffer->parsed_size];
    if(size_left >= strlen(connect_string) && strncmp((char *)data, connect_string, strlen(connect_string)) == 0){
        buffer->parsed_size += strlen(connect_string);
        return Ok;
    }    
    else if(size_left > 5){
        ERROR("Invalid preface %X %X %X %X %X", data[0], data[1], data[2], data[3], data[4]);
    }
    else{
        ERROR("Invalid preface, too short with length %d", size_left);
    }

    return InvaidConnectionPreface;
}

TaskList http2_client_handle_message_async(Http2Client *client, const char *buff, size_t len, CancellationToken *token){
    if(client == NULL){
        ERROR("Client is null");
        return task_list_empty();
    }

#if LOG_LEVEL <= LOG_LEVEL_DEBUG
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
#endif

    ParseBuffer parse_buffer;
    buffers_init_parse_buffer(&parse_buffer, (uint8_t *)buff, len);

    if(client->status == ConnectionPreface){
        LOG_INFO("Connection preface of size %zu", parse_buffer.total_size - parse_buffer.parsed_size);
        Http2InternalStatus status = _connection_preface_message(client, &parse_buffer);
        if(status != Ok){
            ERROR("Connection preface failed\n");
            http2_common_send_goaway(client, ErrorCodeProtocolError);
        }
        client->status = Running;
        LOG_INFO("Connection preface done with %zu bytes left\n", parse_buffer.total_size - parse_buffer.parsed_size);
    }

    uint8_t buffer[4096];

    TaskList task_list = task_list_empty();

    while(parse_buffer.parsed_size < parse_buffer.total_size){
        size_t initial_parsed_size = parse_buffer.parsed_size;
        GenericFrame frame;
        ParseStatus status = http2_frame_parse(&parse_buffer, &frame);
        if(status == ParseStatusNotFullMessage){
            ERROR("Not full message, unable to proceed");
        }
        else if(status != ParseStatusSuccess){
            ERROR("Invalid frame received, sending goaway");
            http2_common_send_goaway(client, ErrorCodeProtocolError);
            break;
        }
        InternalFrameHeader header = http2_frame_get_header(&frame);

        if(header.stream_id == 0){
            default_stream_handle_message_async(client, &frame, token);
            continue;
        }

        Stream *stream = NULL;
        for(size_t i = 0; i < MAX_STREAMS_PER_CLIENT; i++){
            if(client->streams[i].id == header.stream_id && client->streams[i].state != Closed && client->streams[i].state != Idle){
                stream = &client->streams[i];
                break;
            }
        }
        if(stream == NULL){
            if(header.stream_id <= client->highest_client_stream_id){
                continue;
            }
            else{
                for(size_t i = 0; i < MAX_STREAMS_PER_CLIENT; i++){
                    if(client->streams[i].state == Closed || client->streams[i].state == Idle){
                        stream = &client->streams[i];
                        *stream = (Stream){
                            .id = header.stream_id,
                            .state = Idle,
                            .window_size = client->initial_window_size
                        };
                        client->highest_client_stream_id = header.stream_id;
                        break;
                    }
                }
            }
        }
        if(stream == NULL){
            ERROR("Unable to find free stream");
            return task_list;
        }
        
        if(frame.type == RstStream){
            if(stream->state == Idle){
                http2_common_send_goaway(client, ErrorCodeProtocolError);
            }
            else{
                stream->id = 0;
                stream->state = Closed;
            }
            continue;
        }

        Task task = completed_task();
        switch(stream->state){
            case Idle:
                LOG_DEBUG("Handling message for idle stream %d", header.stream_id);
                task = idle_stream_handle_message_async(client, stream, &frame, token);
                break;
            case Open:
                LOG_DEBUG("Handling message for open stream %d", header.stream_id);
                task = open_stream_handle_message_async(client, stream, &frame, token);
                break;
            case HalfClosedRemote:
                LOG_DEBUG("Handling message for half closed (remote) stream %d", header.stream_id);
                task = half_closed_remove_handle_message_async(client, stream, &frame, token);
                break;
            default:
                ERROR("Unable to handle stream in state %d", stream->state);
                exit(EXIT_FAILURE);
        }
        task_list_add_task(&task_list, task);

        LOG_DEBUG("parsed %zu, total %zu", parse_buffer.parsed_size, parse_buffer.total_size);

        if(parse_buffer.parsed_size == initial_parsed_size){
            ERROR("Unable to handle message");
            exit(EXIT_FAILURE);
        }
    }
    LOG_INFO("============== Message handled");

    return task_list;
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


static bool _send(Http2Client *client, uint8_t *data, size_t size){
    return client->send_cb.send(client->send_cb.u_data, data, size);
}
