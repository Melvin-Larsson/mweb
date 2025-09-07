#include "content_server_contract.h"
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define LOG_CONTEXT "ContentServer"
#include "logging.h"

typedef struct{
    const char *name;
    char *(*handle)(void);
}ContentFunction;

static void _setup_signal_handlers();
static void _signal_handler();
static void _crash_handler();
static void _run();

static bool _try_get_content_function(char *key, size_t key_length, ContentFunction *result);
static char *_time_content();
static char *_served_count_content();

static ContentFunction functions[] = {
    {"TIME", _time_content },
    {"SERVED_COUNT", _served_count_content }
};
const size_t content_function_count = sizeof(functions) / sizeof(ContentFunction);

static int _served_count;
static int _socket = 3;

int main(int argc, char **args){
    LOG_TRACE("Content server started");
    _setup_signal_handlers();

    _run();

    return 0;
}

static void _run(){
    while(true){
        uint8_t buffer[1024];
        ssize_t size = read(_socket, buffer, sizeof(buffer));
        if(size < 0){
            ERRNO_ERROR("Failed to read from socket");
            continue;
        }

        for(size_t i = 0; i < size; i++){
            if(i == 24){
                printf("- ");
            }
            printf("%2X ", buffer[i]);
        }
        printf("\n");
        for(size_t i = 0; i < size; i++){
            if(i == 24){
                printf("- ");
            }
            char c = buffer[i] > ' ' && buffer[i] <= '~' ? buffer[i] : '?';
            printf(" %c ", c);
        }
        printf("\n");

        _served_count++;

        uint8_t *data = buffer;
        ParseBuffer parse_buffer;
        buffers_init_parse_buffer(&parse_buffer, data, size);
        while(!parse_buffer_size_is_empty(&parse_buffer)){
            uint8_t request_data[1024];
            Buffer request_data_buffer;
            buffers_init_buffer(&request_data_buffer, request_data, sizeof(request_data));


            ContentRequestMessage message;
            DeserializeStatus status = deserialize_content_request(&parse_buffer, &message, &request_data_buffer);
            if(status != DeserializeStatusOk){
                ERROR("Unable to deserialize request. Reason '%s'", deserialize_status_str(status));
                break;
            }

            uint8_t response_data[1024];
            Buffer response_data_buffer;
            buffers_init_buffer(&response_data_buffer, response_data, sizeof(response_data));
            ReplySerializerContext *reply_ctx = reply_serialier_context_create(&response_data_buffer, message.request_id);
            if(reply_ctx == NULL){
                ERROR("Unable to allocate reply serializer ctx");
                continue;
            }
            for(size_t i = 0; i < message.tag_count; i++){
                LOG_TRACE("Creating response for %.*s", message.tags[i].length, message.tags[i].value);

                ContentFunction function;
                if(!_try_get_content_function((char *)message.tags[i].value, message.tags[i].length, &function)){
                    LOG_WARNING("Unknown tag");
                    continue;
                }

                char *content = function.handle();
                LOG_TRACE("Response for tag '%.*s'is '%s'", message.tags[i].length, message.tags[i].value, content);
                reply_serializer_context_add_content(reply_ctx, content, strlen(content));
                free(content);
            }

            LOG_TRACE("Serialize response");
            size_t reply_size;
            uint8_t *response_message = reply_serializer_context_serialize(reply_ctx, &reply_size);
            if(response_message == NULL){
                ERROR("Unable to serialize response message");
                continue;
            }

            write(_socket, response_message, reply_size);
        }
    }
}

static void _setup_signal_handlers() {
    int crash_signals[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT };
    for (size_t i = 0; i < sizeof(crash_signals)/sizeof(crash_signals[0]); i++) {
        signal(crash_signals[i], _crash_handler);
    }

    signal(SIGTERM, _signal_handler);
    signal(SIGINT, _signal_handler);
}

static void _signal_handler(){
    LOG_INFO("Exiting");
    exit(EXIT_SUCCESS);
}

static void _crash_handler(){
    MessageHeader message = {
        .start_of_message_identifier = START_OF_MESSAGE_IDENTIFIER,
        .request_id = 0,
        .type = ContentServerExit,
        .payload_length = 0
    };
    write(_socket, &message, sizeof(message));
    exit(EXIT_FAILURE);
}

static bool _try_get_content_function(char *key, size_t key_length, ContentFunction *result){
    for(size_t i = 0; i < content_function_count; i++){
        if(strncmp(key, functions[i].name, key_length) == 0){
            *result =  functions[i];
            return true;
        }
    }
    return false;
}

static char *_time_content(){
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    char *time = asctime(local_time);
    char *result = malloc(strlen(time) + 1);
    strcpy(result, time);
    result[strlen(result) - 1] = 0;
    return result;
}

static char *_served_count_content(){
    static int c = 0;
    c++;
    int y = 5 / (c - 10);
    char *buff = malloc(8);
    snprintf(buff, sizeof(buff), "%d", _served_count);
    return buff;
}
