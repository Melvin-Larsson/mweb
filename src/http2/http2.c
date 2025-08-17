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
#include "http2_logging.h"

static void _print_settings(InternalSettingsFrame *settings);
static ParseStatus _parse_priority_data(char *buff, size_t len, InternalPriorityData *result);
static FrameType _get_frame_type(char *buff, size_t len);
static size_t _to_external_frame(InternalFrameHeader frame, char *buffer, size_t buffer_size);
static bool _ignore_frame(ParseBuffer *buffer);
static bool _send(Http2Client *client, uint8_t *data, size_t size);

Http2Client *http2_client_new(Http2SendCb cb){
    assert(cb.send != NULL);
    assert(cb.u_data != NULL);
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
        .send_cb = cb
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
    free(client);
}

Http2InternalStatus _connection_preface_message(Http2Client *client, ParseBuffer *buffer){
    char *connect_string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    size_t size_left = buffer->total_size - buffer->parsed_size;
    if(size_left >= strlen(connect_string) && strncmp((char *)&buffer->data[buffer->parsed_size], connect_string, strlen(connect_string)) == 0){
        buffer->parsed_size += strlen(connect_string);
        return Ok;
    }    

    return InvaidConnectionPreface;
}

void http2_client_handle_message(Http2Client *client, const char *buff, size_t len){
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
        Http2InternalStatus status = _connection_preface_message(client, &parse_buffer);
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
            default_stream_handle_message(client, &frame);
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
                    if(client->streams[i].id == 0){
                        stream = &client->streams[i];
                        *stream = (Stream){
                            .id = header.stream_id,
                            .state = Idle,
                            .window_size = DEFAULT_WINDOW_SIZE
                        };
                        client->highest_client_stream_id = header.stream_id;
                        break;
                    }
                }
            }
        }
        if(stream == NULL){
            ERROR("Unable to find free stream");
            return;
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

        switch(stream->state){
            case Idle:
                LOG_DEBUG("Handling message for idle stream %d", header.stream_id);
                idle_stream_handle_message(client, stream, &frame);
                break;
            case Open:
                LOG_DEBUG("Handling message for open stream %d", header.stream_id);
                open_stream_handle_message(client, stream, &frame);
                break;
            case HalfClosedRemote:
                LOG_DEBUG("Handling message for half closed (remote) stream %d", header.stream_id);
                half_closed_remote_handle_message(client, stream, &frame);
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


static bool _send(Http2Client *client, uint8_t *data, size_t size){
    return client->send_cb.send(client->send_cb.u_data, data, size);
}
