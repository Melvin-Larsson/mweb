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

        _served_count++;

        uint8_t *data = buffer;
        while(size > 0){
            MessageHeader *message = (MessageHeader *)data;
            size_t message_size = sizeof(MessageHeader) + message->payload_length;
            if(message_size > size){
                LOG_WARNING("Partial message received of size %d / (%d + %d). This is not supported", size, sizeof(MessageHeader), message->payload_length);
                break;
            }
            size -= message_size;
            data += message_size;

            if(message->start_of_message_identifier != START_OF_MESSAGE_IDENTIFIER){
                LOG_WARNING("Received invalid start of message identifier 0x%X", message->start_of_message_identifier);
                continue;
            }


            if(message->type == ContentRequest){
                LOG_TRACE("Received content request for %.*s", message->payload_length, message->payload);
                ContentFunction function;
                if(!_try_get_content_function(message->payload, message->payload_length, &function)){
                    LOG_WARNING("Unknown tag %.*s", message->payload_length, message->payload);
                    continue;
                }
                char *response = function.handle();
                uint8_t *buffer = malloc(sizeof(MessageHeader) + strlen(response));
                LOG_DEBUG("Responding with '%s' for tag '%.*s'", response, message->payload_length, message->payload);

                MessageHeader *header = (MessageHeader *)buffer;
                *header = (MessageHeader){
                    .start_of_message_identifier = START_OF_MESSAGE_IDENTIFIER,
                    .type = ContentReply,
                    .payload_length = strlen(response),
                    .request_id = message->request_id,
                };
                memcpy(header->payload, response, header->payload_length);
                write(_socket, buffer, sizeof(MessageHeader) + header->payload_length);

                free(response);
                free(buffer);
            }
            else{
                LOG_WARNING("Invalid request type %d", message->type);
            }
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
