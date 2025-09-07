#include "content_server_proxy.h"
#include "content_server_contract.h"
#include "libgen.h"
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "collections/slot_map.h"
#include "collections/queue.h"

#define MAX_PATH_LENGTH 256

#define member_size(type, member) (sizeof( ((type *)0)->member ))

#define LOG_CONTEXT "ContentServerProxy"
#include "logging.h"

#define RETURN_ON_FAILURE(status)\
    if(status != ContentServerOk){\
        return status;\
    }\

struct ContentServer{
    int process_id;
    int eventfd;
    int client_socket;
    int server_socket;
    SlotMap *request_slot_map;
    Queue *request_queue;
};

typedef struct{
    void (*cb)(void *ctx);
    void *ctx;
}Callback;

typedef struct{
    uint8_t *request;
    size_t request_length;
    Callback callback;
    uint8_t **result;
    size_t *size;
}Request;


static void _run_content_server(int socket);
static ContentServerStatus _assure_content_server_started(ContentServer *server);
static ContentServerStatus _start_content_server(ContentServer *server);
static bool _find_content_server_executable(char *result, size_t buffer_size);
static bool _try_set_nonblocking(int sockfd);

static void _handle_data_received(ContentServer *server);
static void _handle_queue_item(ContentServer *server);

ContentServer *content_server_new(){
    ContentServer *server = malloc(sizeof(ContentServer));
    SlotMap *request_slot_map = slot_map_new(sizeof(Request));
    Queue *request_queue = queue_new(sizeof(Request));
    if(server == NULL || request_slot_map == NULL || request_queue == NULL){
        free(server);
        slot_map_free(request_slot_map);
        queue_free(request_queue);
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
        .client_socket = sockets[1],
        .eventfd = eventfd(0, 0),
        .request_slot_map = request_slot_map,
        .request_queue = request_queue
    };

    if(server->eventfd == -1){
        ERRNO_ERROR("Unable to create event fd");
        goto exit_sockets;
    }

    return server;

exit_event_fd:
    close(server->eventfd);
exit_sockets:
    close(sockets[0]);
    close(sockets[1]);
exit_server:
    free(server);
    slot_map_free(request_slot_map);
    queue_free(request_queue);
    return NULL;
}

ContentServerStatus content_server_run(ContentServer *server){
    int epollfd = epoll_create1(0);
    if(epollfd < 0){
        ERRNO_ERROR("Failed creating epoll");
        return ContentServerUnableToEpoll;
    }

    struct epoll_event socket_cfg = {
        .events = EPOLLIN,
        .data.fd = server->client_socket
    };
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, server->client_socket, &socket_cfg) < 0){
        ERRNO_ERROR("Failed to listen");
        goto exit_epoll;
    }

    struct epoll_event event_cfg = {
        .events = EPOLLIN,
        .data.fd = server->eventfd
    };
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, server->eventfd, &event_cfg) < 0){
        ERRNO_ERROR("Failed to listen");
        goto exit_epoll;
    }

    struct epoll_event events[16];
    while(true){
        LOG_DEBUG("Waiting for epoll event");
        int epoll_result = epoll_wait(epollfd, events, sizeof(events)/sizeof(struct epoll_event), -1);
        LOG_TRACE("Received %d epoll events", epoll_result);
        if(epoll_result == -1){
            if(errno == EINTR){
                LOG_TRACE("Program signal received, ignoring");
                continue;
            }
            else{
                ERRNO_ERROR("Wait failed");
                goto exit_epoll;
            }

        }else if(epoll_result == 0){
            ERROR("What?\n");
            continue;
        }

        for(size_t i = 0; i < epoll_result; i++){
            struct epoll_event event = events[i];
            if(event.data.fd == server->eventfd){
                LOG_TRACE("Handle queue items");
                uint64_t buff;
                read(server->eventfd, &buff, sizeof(buff));
                _handle_queue_item(server);
            }
            else if(event.data.fd == server->client_socket){
                LOG_TRACE("Handle data received");
                _handle_data_received(server);
                LOG_TRACE("Received data handled");
            }
            else{
                LOG_WARNING("Unknown event received");
            }
        }    

    }

exit_epoll:
    close(epollfd);
    return ContentServerUnableToEpoll;
}

static void _handle_data_received(ContentServer *server){
    uint8_t buff[1024];
    ssize_t data_read = read(server->client_socket, buff, sizeof(buff));
    if(data_read <= 0){
        ERRNO_ERROR("Failed when reading data");
        return;
    }
    if(data_read == sizeof(buff)){
        LOG_WARNING("Too much data received, buffer is too small");
    }

    LOG_TRACE("Response received of size %d", data_read);

    for(size_t i = 0; i < sizeof(MessageHeader); i++){
        printf("%2X ", buff[i]);
    }
    printf("\n");

    //FIXME: Maybe limit parsing code to contract.c. I think...
    MessageHeader *response = (MessageHeader *)buff;
    if(response->type != ContentReply){
        if(response->type == ContentServerExit){
            LOG_WARNING("Content server exited. Restarting...");
            _start_content_server(server);
        }
        else{
            LOG_WARNING("Invalid response type %d", response->type);
        }
        return;
    }
    assert(sizeof(response->request_id) == sizeof(SlotMapHandle));
    SlotMapHandle handle;
    memcpy(&handle, &response->request_id, sizeof(SlotMapHandle));

    Request request;
    if(!slot_map_try_get(server->request_slot_map, handle, &request)){
        LOG_TRACE("No entry in slotmap with id %d", response->request_id);
        return;
    }

    LOG_TRACE("Handling response with cb %X", request.callback.cb);

    *request.result = malloc(data_read);
    memcpy(*request.result, buff, data_read);
    *request.size = data_read;

    Callback cb = request.callback;
    LOG_TRACE("Calling callback");
    cb.cb(cb.ctx);
    LOG_TRACE("Callback called");

    slot_map_remove(server->request_slot_map, handle);
}

static void _handle_queue_item(ContentServer *server){
    Request request;
    while(queue_try_dequeue(server->request_queue, &request)){
        _assure_content_server_started(server);
        SlotMapHandle handle;
        if(!slot_map_try_add(server->request_slot_map, &request, &handle)){
            ERROR("Unable to add callback to slotmap");
            return;
        }
        LOG_DEBUG("Added request with cb %X", request.callback.cb);

        //FIXME: This is a BIG hack
        size_t offset = offsetof(MessageHeader, request_id);
        assert(sizeof(SlotMapHandle) == member_size(MessageHeader, request_id));
        memcpy(request.request + offset, &handle, sizeof(SlotMapHandle));

        LOG_TRACE("Sending request of size %zu: '%.*s'", request.request_length, request.request_length, request.request);
        write(server->client_socket, request.request, request.request_length);

        free(request.request);
    }
}

typedef struct{
    ContentServer *server;
    uint8_t *result;
    size_t result_size;
    TaskList (*cb)(void *ctx, ContentResult result);
    void *ctx;
}AsyncTaskCtx;

typedef struct{
    ContentServer *server;
    uint8_t *request;
    size_t request_length;
    uint8_t **result;
    size_t *result_size;
}TaskRunnerCtx;

static void _enqueue_request(TaskRunner task_runner, void (*cb)(void *ctx), void *ctx){
    TaskRunnerCtx *runner_ctx = (TaskRunnerCtx *)task_runner.ctx;
    ContentServer *server = runner_ctx->server;

    LOG_TRACE("Enqueueing request for content server");

    Request request = {
        .request = runner_ctx->request,
        .request_length = runner_ctx->request_length,
        .callback = (Callback){
            .cb = cb,
            .ctx = ctx
        },
        .result = runner_ctx->result,
        .size = runner_ctx->result_size
    };

    queue_enqueue(server->request_queue, &request);
    uint64_t buff = 1;
    write(server->eventfd, &buff, sizeof(buff));

    free(runner_ctx);
}

static TaskList _on_task_completed(AsyncTask task){
    AsyncTaskCtx *task_ctx = (AsyncTaskCtx *)task.ctx;
    uint8_t buffer_data[1024];
    Buffer buffer;
    buffers_init_buffer(&buffer, buffer_data, sizeof(buffer_data));
    ParseBuffer parse_buffer;
    buffers_init_parse_buffer(&parse_buffer, task_ctx->result, task_ctx->result_size);
    ContentReplyMessage reply;

    DeserializeStatus deserialize_status = deserialize_content_reply(&parse_buffer, &reply, &buffer);
    if(deserialize_status != DeserializeStatusOk){
        ERROR("Unable to deserialize content reply: %s", deserialize_status_str(deserialize_status));
        ContentResult result = {.status = ContentServerDeserializeFailure};
        return task_ctx->cb(task_ctx->ctx, result);
    }

    Content content[128];
    for(size_t i = 0; i < reply.content_count; i++){
        content[i] = (Content){
            .content = reply.content[i].value,
            .length = reply.content[i].length
        };
    }

    ContentResult result = {
        .status = ContentServerOk,
        .content = content,
        .content_count = reply.content_count,
    };
    LOG_TRACE("Calling task completion callback");
    TaskList task_list = task_ctx->cb(task_ctx->ctx, result);
    LOG_TRACE("Task completed");

    free(task_ctx->result);
    free(task_ctx);

    return task_list;
}

Task content_server_get_content_async(ContentServer *server, const Tag *tags, size_t tag_count, TaskList (*cb)(void *ctx, ContentResult content), void *ctx, CancellationToken *token){
    assert(server != NULL);
    assert(tags != NULL);
    assert(cb != NULL);

    LOG_TRACE("Requesting content from content server");
    AsyncTaskCtx *task_ctx = malloc(sizeof(AsyncTaskCtx));
    *task_ctx = (AsyncTaskCtx){
        .cb = cb,
        .ctx = ctx,
        .result = NULL,
        .result_size = 0,
        .server = server
    };
    LOG_DEBUG("Callback for content creationg at %X", task_ctx->cb);

    uint8_t request_buffer[1024];
    Buffer buffer;
    buffers_init_buffer(&buffer, request_buffer, sizeof(request_buffer));
    RequestSerializerContext *serializer_ctx = request_serialier_context_create(&buffer, 0);

    for(size_t i = 0; i < tag_count; i++){
        request_serializer_context_add_tag(serializer_ctx, tags[i].tag, tags[i].length);
    }
    size_t request_size;
    uint8_t *stack_request = request_serializer_context_serialize(serializer_ctx, &request_size);

    if(stack_request == NULL){
        ERROR("Ran out of buffer space");
        cb(ctx, (ContentResult) {.status = ContentServerOutOfMemory});
        return completed_task();
    }

    uint8_t *heap_request = malloc(request_size);
    if(heap_request == NULL){
        ERROR("Unable to allocate memory");
        cb(ctx, (ContentResult) {.status = ContentServerOutOfMemory});
        return completed_task();
    }
    memcpy(heap_request, stack_request, request_size);

    TaskRunnerCtx *taskrunner_ctx = malloc(sizeof(TaskRunnerCtx));
    *taskrunner_ctx = (TaskRunnerCtx){
        .request = heap_request,
        .request_length = request_size,
        .server = server,
        .result = &task_ctx->result,
        .result_size = &task_ctx->result_size
    };
    TaskRunner runner = {
        .ctx = taskrunner_ctx,
        .start_async = _enqueue_request
    };

    return async_task(runner, _on_task_completed, task_ctx);
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
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
            ERRNO_ERROR("Unable to configure child process to receive parent kill signal");
        }
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

static bool _try_set_nonblocking(int sockfd) {
    int flags;

    if ((flags = fcntl(sockfd, F_GETFL, 0)) == -1) {
        ERRNO_ERROR("Unable to get socket flags");
        return false;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        ERRNO_ERROR("Unable to make socket non blocking");
        return false;
    }

    return true;
}
