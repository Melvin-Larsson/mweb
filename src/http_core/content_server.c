#include "content_server.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_CONTEXT "ContentServer"
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

ContentServerStatus content_server_get_content(ContentServer *server, const char *tag, char **result, size_t *result_length){
    RETURN_ON_FAILURE(_assure_content_server_started(server));

    char buff[] = "Hello";
    write(server->client_socket, buff, sizeof(buff));

    *result = malloc(128);
    *result_length = read(server->client_socket, *result, 128);

    return ContentServerOk;
}

static ContentServerStatus _assure_content_server_started(ContentServer *server){
    if(server->process_id > 0){
        int status;
        pid_t result = waitpid(server->process_id, &status, WNOHANG);
        if(result == 0){
            LOG_TRACE("Child alive");
            return ContentServerOk;
        }
        LOG_TRACE("Child exited");
    }

    LOG_TRACE("Starting child");
    pid_t pid = fork();
    if(pid == 0){
        _run_content_server(server->server_socket);
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

static void _run_content_server(int socket){
    for(size_t i = 0; i < 4; i++){
        uint8_t buffer[1024];
        ssize_t size = read(socket, buffer, sizeof(buffer));
        if(size < 0){
            ERRNO_ERROR("Failed to read from socket");
            continue;
        }

        printf("Read from owner: %.*s\n", (int)size, buffer);
        if(strncmp((char *)buffer, "Hello", size) == 0){
            uint8_t result[] = "World!";
            write(socket, result, sizeof(result));
        }
        else{
            uint8_t result[] = "Wrong!";
            write(socket, result, sizeof(result));
        }
        int y = 10 / (i - 3);
    }
}
