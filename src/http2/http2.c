#include "http2/http2.h"
#include <string.h>
#include "inttypes.h"
#include "stdio.h"
#include "stdlib.h"
#include "assert.h"

#include "http2_frame.h"
#include "http2_logging.h"


#define min(x, y) ((x) < (y) ? (x) : (y))

#define PRIORITY_DATA_LENGTH 5

static void _print_settings(InternalSettingsFrame *settings);

static ParseStatus _parse_priority_data(char *buff, size_t len, InternalPriorityData *result);

static FrameType _get_frame_type(char *buff, size_t len);
static size_t _to_external_frame(InternalFrameHeader frame, char *buffer, size_t buffer_size);
    
void http2_handle_message(void *data, const ClientHandle client, char *buff, size_t len){
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

    char *connect_string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if(len >= strlen(connect_string) && strncmp(buff, connect_string, strlen(connect_string)) == 0){
        char *frame_bytes = buff + strlen(connect_string);
        size_t frame_size = len - strlen(connect_string);

        ParseBuffer buffer = {
            .data = frame_bytes,
            .data_length = frame_size,
            .parsed_length = 0
        };

        LOG_DEBUG("Parsing frame of size %zu", frame_size);

        FrameType type = http2_frame_get_frame_type(frame_bytes, frame_size);
        if(type == Invalid){
            LOG_DEBUG("Invalid frame type %d\n");
        }
        else if(type == Settings){
            InternalSettingsFrame settings;
            ParseStatus status = http2_frame_parse_settings_frame(&buffer, &settings);
            if(status != ParseStatusSuccess){
                LOG_DEBUG("Failed to parse settings frame. Reason %d", status);
            }
            else{
                http2_frame_print_settings(&settings);
                size_t bytes_left = buffer.data_length - buffer.parsed_length;
                if(bytes_left > 0){
                    LOG_DEBUG("I still have %zu bytes in the buffer", bytes_left);
                    for(size_t i = buffer.parsed_length; i < buffer.data_length; i++){
                        printf("%X ", buffer.data[i]);
                    }
                    printf("\n");
                }
            }
        }
        else{
            LOG_DEBUG("Received unexpected message of type %d", type);
        }
    }
    else{
        ERROR("Unknown header");
    }
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
