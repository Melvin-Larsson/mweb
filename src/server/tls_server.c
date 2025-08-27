#include "tls_server.h"
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include "errno.h"
#include "server_worker.h"

#define LOG_CONTEXT "TlsServer"
#include "logging.h"

typedef struct{
    TlsServer *server;
    size_t worker_index;
}WorkerCtx;

struct TlsServer{
    TlsServerConfiguration configuration;

    int socket;
    int stopfd;

    size_t actual_thread_count;
    pthread_t *threads;
    ServerWorker **workers;
    WorkerCtx *worker_ctxs;
};

static void *_run_worker(void *data);
static void _listen(TlsServer *server);

static int _create_listen_socket(int port);
static ServerWorker *_schedule_worker(TlsServer *server);

static void _on_receive(void *u_data, void *u_client_data, const ClientHandle handle, char *data, size_t length);
static void _on_connect(void *u_data, const ClientHandle handle);
static void _on_disconnect(void *u_data, void *u_client_data, const ClientHandle handle);

static ClientHandle _to_client_handle(const TlsServerClient client);

TlsServerConfiguration tls_server_default_configuration(int port, const char *cert_file_path, const char *private_key_path){
    return (TlsServerConfiguration){
        .port = port,
        .cert_file_path = cert_file_path,
        .private_key_path = private_key_path,
        .thread_count = sysconf(_SC_NPROCESSORS_ONLN)
    };
}

TlsServer *tls_server_new(TlsServerConfiguration configuration){
    LOG_INFO("Creating tls server with %d threads, cert at '%s' and private key at '%s'", configuration.thread_count, configuration.cert_file_path, configuration.private_key_path);
    TlsServer *server = malloc(sizeof(TlsServer));
    pthread_t *threads = calloc(configuration.thread_count, sizeof(pthread_t));
    ServerWorker **workers = calloc(configuration.thread_count, sizeof(ServerWorker *));
    WorkerCtx *worker_ctx = calloc(configuration.thread_count, sizeof(WorkerCtx));
    if(server == NULL || threads == NULL || workers == NULL || worker_ctx == NULL){
        goto exit_worker_ctx;
    }

    for(size_t i = 0; i < configuration.thread_count; i++){
        worker_ctx[i] = (WorkerCtx){
            .server = server,
            .worker_index = i
        };
    }
    ServerWorkerConfig worker_configuration = {
        .cert_file_path = configuration.cert_file_path,
        .private_key_path = configuration.private_key_path
    };
    for(size_t i = 0; i < configuration.thread_count; i++){
        workers[i] = server_worker_new(worker_configuration);
        if(workers[i] == NULL){
            goto exit_workers;
        }
        server_worker_set_ssl_ctx_cb(workers[i], configuration.ssl_ctx_callback.invoke, configuration.ssl_ctx_callback.u_data);
        server_worker_set_connect_callback(workers[i], _on_connect, &worker_ctx[i]);
        server_worker_set_disconnect_callback(workers[i], _on_disconnect, &worker_ctx[i]);
        server_worker_set_receive_callback(workers[i], _on_receive, &worker_ctx[i]);
        //TODO: Set callbacks
    }

    int socket = _create_listen_socket(configuration.port);
    if(socket <= 0){
        goto exit_workers;
    }

    int stopfd = eventfd(0, 0);
    if(stopfd <= 0){
        ERRNO_ERROR("Unable to create stopfd");
        goto exit_socket;
    }

    *server = (TlsServer){
        .configuration = configuration,
        .socket = socket,
        .threads = threads,
        .workers = workers,
        .worker_ctxs = worker_ctx,
        .stopfd = stopfd
    };

    return server;
exit_socket:
    close(socket);
exit_workers:
    for(size_t i = 0; i < configuration.thread_count; i++){
        server_worker_free(workers[i]);
    }
exit_worker_ctx:
    free(workers);
    free(threads);
    free(server);
    return NULL;
}

void tls_server_free(TlsServer *server){
    for(size_t i = 0; i < server->configuration.thread_count; i++){
        ServerWorker *worker = server->workers[i];
        server_worker_request_stop(worker);
    }

    for(size_t i = 0; i < server->actual_thread_count; i++){
        pthread_join(server->threads[i], NULL);
    }   

    for(size_t i = 0; i < server->configuration.thread_count; i++){
        ServerWorker *worker = server->workers[i];
        server_worker_free(worker);
    }

    free(server->threads);
    free(server->worker_ctxs);
    free(server->workers);

    server->threads = NULL;
    server->worker_ctxs = NULL;
    server->workers = NULL;

    if(server->socket > 0){
        close(server->socket);
        server->socket = -1;
    }

    if(server->stopfd > 0){
        close(server->stopfd);
        server->stopfd = -1;
    }

    free(server);
}

void tls_server_run(TlsServer *server){
    server->actual_thread_count = server->configuration.thread_count;
    for(size_t i = 0; i < server->configuration.thread_count; i++){
        if(pthread_create(&server->threads[i], 0, _run_worker, &server->worker_ctxs[i]) != 0){
            ERROR("Unable to create %d worker threads. Will only use %d workers", server->configuration, i);
            server->actual_thread_count = i;
            break;
        }
    }

    if(server->actual_thread_count == 0){
        ERROR("Was not able to create any worker threads, exiting... ");
        return;
    }

    _listen(server);
}

static void _listen(TlsServer *server){
    int epollfd = epoll_create1(0);
    if(epollfd < 0){
        ERRNO_ERROR("Failed creating epoll");
        return;
    }

    struct epoll_event socket_cfg = {
        .events = EPOLLIN,
        .data.fd = server->socket
    };
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, server->socket, &socket_cfg) < 0){
        ERRNO_ERROR("Failed to listen");
        goto exit_epoll;
    }

    struct epoll_event stop_cfg = {
        .events = EPOLLIN,
        .data.fd = server->stopfd
    };
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, server->stopfd, &stop_cfg) < 0){
        ERRNO_ERROR("Failed to listen");
        goto exit_epoll;
    }

//     struct epoll_event stop_cfg = {
//         .events = EPOLLIN,
//         .data.fd = worker->stopfd
//     };
//     if(epoll_ctl(worker->epollfd, EPOLL_CTL_ADD, worker->stopfd, &stop_cfg) < 0){
//         ERRNO_ERROR("Failed to listen on stop signal");
//         status = ServerWorkerListenError;
//         goto exit_socket;
//     }

    struct epoll_event events[16];
    while(true){
        int epoll_result = epoll_wait(epollfd, events, sizeof(events)/sizeof(struct epoll_event), -1);
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
            if(event.data.fd == server->stopfd){
                LOG_DEBUG("Stop requested. Stopping");
                uint64_t buff;
                read(server->stopfd, &buff, sizeof(buff));
                goto exit_epoll;
            }
            if(event.data.fd == server->socket){
                struct sockaddr_storage addr;
                socklen_t addrlen = sizeof(addr);
                int client_socket = accept(server->socket, (struct sockaddr *)&addr, &addrlen);
                if(client_socket <= 0){
                    ERRNO_ERROR("Invalid client socket");
                    continue;
                }
                ServerWorker *worker = _schedule_worker(server);
                assert(worker != NULL);
                if(!server_worker_add_client(worker, client_socket, addr)){
                    ERROR("Unable to add socket to worker %X, closing socket", worker);
                    close(client_socket);
                }
            }
        }    
    }

exit_epoll:
    close(epollfd);
    LOG_INFO("Stopped");
}

void tls_server_request_stop(TlsServer *server){
    LOG_TRACE("Requesting stop");
    uint64_t buff = 1;
    write(server->stopfd, &buff, sizeof(buff));
    LOG_DEBUG("Stop requested");
}

static ServerWorker *_schedule_worker(TlsServer *server){
    ServerWorker *min_worker = server->workers[0];
    unsigned int min_workload = server_worker_get_workload_weight(min_worker);
    for(size_t i = 1; i < server->actual_thread_count; i++){
        ServerWorker *worker = server->workers[i];
        unsigned int workload = server_worker_get_workload_weight(worker);
        if(workload < min_workload){
            min_worker = worker;
            min_workload = workload;
        }
    }
    return min_worker;
}

static void *_run_worker(void *data){
    WorkerCtx *ctx = (WorkerCtx *)data;
    ServerWorker *worker = ctx->server->workers[ctx->worker_index];
    LOG_TRACE("Running worker %zu using data at %X", ctx->worker_index, worker);
    server_worker_run(worker);

    return NULL;
}

ServerStatus tls_server_send(TlsServer *server, const TlsServerClient client, const uint8_t *buffer, size_t buffer_size){
    LOG_TRACE("Send");
    ServerWorker *worker = server->workers[client.worker];
    ClientHandle handle = _to_client_handle(client);
    ServerWorkerStatus status = server_worker_send(worker, handle, (const char *)buffer, buffer_size);
    if(status == ServerWorkerClientDisconnected){
        return ServerStatusClientDisconnected;
    }
    assert(status == ServerWorkerStatusOk);
    return ServerStatusOk;
}

ServerStatus tls_server_enqueue_client_work(TlsServer *server, const TlsServerClient client, void (*work)(void *u_data), void *u_data){
    LOG_TRACE("Enqueue client work");
    ServerWorker *worker = server->workers[client.worker];
    ClientHandle handle = _to_client_handle(client);
    ServerWorkerStatus status = server_worker_enqueue_client_work(worker, handle, work, u_data);
    if(status == ServerWorkerClientDisconnected){
        return ServerStatusClientDisconnected;
    }
    assert(status == ServerWorkerStatusOk);
    return ServerStatusOk;
}

ServerStatus tls_server_attach_client_data(TlsServer *server, const TlsServerClient client, void *u_client_data){
    ClientHandle handle = _to_client_handle(client);
    assert(client.worker < server->actual_thread_count);
    ServerWorker *worker = server->workers[client.worker];
    ServerWorkerStatus status = server_worker_attach_client_data(worker, handle, u_client_data);
    if(status == ServerWorkerClientDisconnected){
        return ServerStatusClientDisconnected;
    }
    assert(status == ServerWorkerStatusOk);
    return ServerStatusOk;
}

static void _on_receive(void *u_data, void *u_client_data, const ClientHandle handle, char *data, size_t length){
    WorkerCtx *ctx = (WorkerCtx *)u_data;
    TlsServer *server = ctx->server;
    if(server->configuration.receive_callback.invoke){
        server->configuration.receive_callback.invoke(server->configuration.receive_callback.u_data, u_client_data, (uint8_t *)data, length);
    }
}
static void _on_connect(void *u_data, const ClientHandle handle){
    WorkerCtx *ctx = (WorkerCtx *)u_data;
    TlsServer *server = ctx->server;
    if(server->configuration.connect_callback.invoke){
        TlsServerClient client = {
            .index = handle.index,
            .generation = handle.generation,
            .worker = ctx->worker_index,
        };
        server->configuration.connect_callback.invoke(server->configuration.receive_callback.u_data, client);
    }
}
static void _on_disconnect(void *u_data, void *u_client_data, const ClientHandle handle){
    WorkerCtx *ctx = (WorkerCtx *)u_data;
    TlsServer *server = ctx->server;
    if(server->configuration.disconnect_callback.invoke){
        server->configuration.disconnect_callback.invoke(server->configuration.disconnect_callback.u_data, u_client_data);
    }   
}

static int _create_listen_socket(int port){
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0){
        perror("Socket fail");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0){
        ERRNO_ERROR("Failed to set socket options");
        return -1;
    }

    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
        ERRNO_ERROR("Failed to set socket options");
        return -1;
    }

    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = INADDR_ANY;

    if(bind(sockfd, (struct sockaddr *)&address, addrlen) < 0){
        ERRNO_ERROR("Bind failed");
        return -1;
    }

    if(listen(sockfd, 128) < 0){
        ERRNO_ERROR("Listen");
        return -1;
    }

    return sockfd;
}

static ClientHandle _to_client_handle(const TlsServerClient client){
    return (ClientHandle){
        .index = client.index,
        .generation = client.generation
    };
}
