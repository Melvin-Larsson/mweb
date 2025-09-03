#include "content_server_proxy.h"
#include "content_server_contract.h"
#include "libgen.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_PATH_LENGTH 256

#define LOG_CONTEXT "ContentServerProxy"
#include "logging.h"

#define RETURN_ON_FAILURE(status)\
    if(status != ContentServerOk){\
        return status;\
    }\

struct ContentServer{
    int process_id;
    int client_socket;
    int server_socket;
};

static void _run_content_server(int socket);
static ContentServerStatus _assure_content_server_started(ContentServer *server);
static ContentServerStatus _start_content_server(ContentServer *server);
static bool _find_content_server_executable(char *result, size_t buffer_size);

ContentServer *content_server_new(){
    ContentServer *server = malloc(sizeof(ContentServer));
    if(server == NULL){
        return NULL;
    }

    int sockets[2];
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0){
        ERRNO_ERROR("Unable to create socket pair");
        goto exit_server;
    }

    *server = (ContentServer){
        .process_id = 0,
        .server_socket = sockets[0],
        .client_socket = sockets[1]
    };

    return server;

exit_server:
    free(server);
    return NULL;
}

ContentServerStatus content_server_get_content(ContentServer *server, const char *tag, size_t tag_length, char **result, size_t *result_length){
    RETURN_ON_FAILURE(_assure_content_server_started(server));

    for(size_t i = 0; i < 3; i++){
        LOG_TRACE("Get content for tag '%.*s'", tag_length, tag);
        uint8_t buff[1024];
        MessageHeader *header = (MessageHeader *)buff;
        *header = (MessageHeader){
            .start_of_message_identifier = START_OF_MESSAGE_IDENTIFIER,
            .type = ContentRequest,
            .payload_length = tag_length,
            .request_id = 1,
        };
        memcpy(header->payload, tag, header->payload_length);
        write(server->client_socket, buff, sizeof(MessageHeader) + header->payload_length);

        read(server->client_socket, buff, sizeof(buff));
        MessageHeader *response = (MessageHeader *)buff;
        if(response->type != ContentReply){
            if(response->type == ContentServerExit){
                LOG_WARNING("Content server exited. Restarting...");
                RETURN_ON_FAILURE(_start_content_server(server));
            }
            else{
                LOG_WARNING("Invalid response type %d", response->type);
            }
            continue;
        }
        *result = malloc(response->payload_length);
        if(*result == NULL){
            return ContentServerOutOfMemory;
        }

        memcpy(*result, response->payload, response->payload_length);
        *result_length = response->payload_length;
        return ContentServerOk;
    }

    return ContentServerUnableToStartServer;
}

static ContentServerStatus _assure_content_server_started(ContentServer *server){
    LOG_TRACE("Starting content server");
    if(server->process_id > 0){
        int status;
        pid_t result = waitpid(server->process_id, &status, WNOHANG);
        if(result == 0){
            LOG_TRACE("Child alive");
            return ContentServerOk;
        }
        LOG_TRACE("Child exited");
    }
    
    return _start_content_server(server);
}

static ContentServerStatus _start_content_server(ContentServer *server){
    LOG_TRACE("Starting child");
    pid_t pid = fork();
    if(pid == 0){
        close(server->client_socket);
        if(dup2(server->server_socket, 3) == -1){
            ERRNO_ERROR("Unable to create duplicate socket to fd 3 for content server");
            exit(EXIT_FAILURE);
        }
        char content_server_exec_path[MAX_PATH_LENGTH];
        if(!_find_content_server_executable(content_server_exec_path, sizeof(content_server_exec_path))){
            ERROR("Unable to locate content server executable");
            exit(EXIT_FAILURE);
        }
        LOG_TRACE("Running '%s'", content_server_exec_path);
        if(execl(content_server_exec_path, "content-server", NULL) == -1){
            ERRNO_ERROR("Unable to exec content server");
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }
    else if(pid < 0){
        ERRNO_ERROR("Unable to start content server");
        return ContentServerUnableToStartServer;
    }
    else{
        server->process_id = pid;
    }

    return ContentServerOk;
}

static bool _find_content_server_executable(char *result, size_t buffer_size){
    char full_path[MAX_PATH_LENGTH];
    ssize_t full_path_length = readlink("/proc/self/exe", full_path, buffer_size - 1);
    if (full_path_length == -1) {
        ERRNO_ERROR("Unable to locate current executable");
    }
    else if(full_path_length == MAX_PATH_LENGTH){
        ERROR("Path too current program is too long");
        return false;
    }

    full_path[full_path_length] = '\0';

    char *dir = dirname(full_path);
    size_t result_length = snprintf(result, buffer_size, "%s/content-server", dir);

    if(result_length >= buffer_size){
        ERROR("Content server path buffer too small");
        return false;
    }
    return true;
}
