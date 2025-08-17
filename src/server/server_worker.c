#include "server_worker.h"
#include <assert.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include "fcntl.h"

#define LOG_DEBUG_ENABLED

#define LOG_INFO(format, ...) printf("[ServerWorker INFO] " format "\n", ##__VA_ARGS__)

#ifdef LOG_DEBUG_ENABLED
    static int _ssl_error_cb(const char *str, size_t len, void *u){
        fprintf(stderr, "[ServerWorker SSL Error] %s\n", str);
        return 1;
    }

#define LOG_DEBUG(format, ...) printf("[ServerWorker Debug] " format "\n", ##__VA_ARGS__)
#define ERROR(format, ...) fprintf(stderr,"[ServerWorker Error] " format "\n", ##__VA_ARGS__)
#define ERRNO_ERROR(format, ...) fprintf(stderr,"[ServerWorker Error] " format "\n\t Reason: %s\n", strerror(errno), ##__VA_ARGS__)
#define SSL_ERROR(format, ...) fprintf(stderr,"[ServerWorker Error] " format "\n", ##__VA_ARGS__); ERR_print_errors_cb(_ssl_error_cb, NULL)
#else
#define LOG_DEBUG(format, ...)
#define ERROR(format, ...)
#define SSL_ERORR(format, ...)
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

#define CLIENT_BUFFER_DEFAULT_SIZE 16
#define CLIENT_BUFFER_GROWTH_RATE 1.5

#define WRITE_QUEUE_DEFAULT_SIZE 16
#define WRITE_QUEUE_GROWTH_RATE 1.5

typedef enum{
    Handshake = 1,
    Stopped = 2,
    Idle = 4,
    Reading = 8,
    Writing = 16,
}ClientStatus;

typedef struct{
    char *data;
    size_t buffer_size;
    size_t used_size;
}DataBuffer;

typedef struct{
    bool has_been_connected;
    volatile ClientStatus status;

    pthread_mutex_t write_lock;

    int socket;
    struct sockaddr_storage address;

    SSL *ssl;
    
    DataBuffer in_flight_out_buffer;
    DataBuffer out_buffer;

    void *u_client_data;
    ClientHandle handle;
}Client;

typedef struct{
    volatile uint64_t generation;
    atomic_long accessor_count; 
    pthread_cond_t no_accessors;
    Client *client;
}ClientEntry;

typedef struct{
    ClientEntry *clients;
    size_t client_buffer_size;
}ClientBuffer;

typedef struct{
    pthread_mutex_t lock;
    int enqueu_event_fd;
    ClientHandle *clients;
    size_t queue_size;
    size_t enqueue;
    size_t dequeue;
}ClientQueue;

typedef struct{
    void *u_data;
    void (*invoke)(void *u_data, void *u_client_data, const ClientHandle client, char *received, size_t size);
}ReceivedCallback;

typedef struct{
    void *u_data;
    void (*invoke)(void *u_data, const ClientHandle client);
}ConnectCallback;

typedef struct{
    void *u_data;
    void (*invoke)(void *u_data, void *u_client_data, const ClientHandle client);
}DisconnectCallback;

typedef struct{
    void *u_data;
    bool (*invoke)(void *u_data, SSL_CTX *ctx);
}ConfigureSSLCtxCallback;

struct ServerWorker{
    SSL_CTX *ssl_ctx;
    int socket;
    int stopfd;
    int epollfd;

    ClientBuffer client_buffer;

    ReceivedCallback receivedCallback;
    ConnectCallback connectCallback;
    DisconnectCallback disconnectCallback;

    ConfigureSSLCtxCallback sslCtxCallback;

    ClientQueue write_queue;

    ServerWorkerConfig config;
};

static bool _client_buffer_initialize(ClientBuffer *buffer);
static void _client_buffer_clear(ClientBuffer *buffer);
static bool _client_buffer_add(ClientBuffer *buffer, Client *client);
static void _client_buffer_remove(ClientBuffer *buffer, Client *client);
static void _client_buffer_defragment(ClientBuffer *buffer);
static Client *_client_buffer_get_client(ServerWorker *worker, ClientHandle hande);
static void _client_buffer_release_client(ServerWorker *worker, ClientHandle hande);

static void _data_buffer_initialize_empty(DataBuffer *buffer);
static bool _data_buffer_initialize_with_data(DataBuffer *buffer, const char *data, size_t data_len);
static void _data_buffer_clear(DataBuffer *buffer);
static bool _data_buffer_add(DataBuffer *buffer, const char *data, size_t data_len);

static bool _client_queue_initialize(ClientQueue *queue);
static void _client_queue_clear(ClientQueue *queue);
static bool _client_queue_enqueue(ClientQueue *queue, ClientHandle handle);
static bool _client_queue_dequeue(ClientQueue *queue, ClientHandle *result);
static size_t _client_queue_dequeue_n(ClientQueue *queue, ClientHandle *result, size_t buffer_size);
static bool _client_queue_resize_without_lock(ClientQueue *queue, size_t new_size);


static SSL_CTX * _create_ssl_context(ServerWorkerConfig *config);
static int _create_listen_socket(int port);
static ServerWorkerStatus _listen(ServerWorker *worker);

static Client * _accept_client(ServerWorker *worker);
static void _handle_write_signal(ServerWorker *worker);
static void _handle_client_write(ServerWorker *worker, Client *client);
static void _handle_client_read(ServerWorker *worker, Client *client);
static void _handle_client_handshake(ServerWorker *worker, Client *client);
static void _disconnect_all_clients(ServerWorker *worker);
static void _disconnect_and_free_client(ServerWorker *worker, Client *client);

static void _client_set_status(ServerWorker *worker, Client *client, ClientStatus status);

static int _ip_str(struct sockaddr *sockaddr, char *result, size_t buffer_size);
static bool _set_nonblocking(int fd);
static bool _try_check_is_nonblocking(int fd, bool *result);

ServerWorker *server_worker_new(ServerWorkerConfig config){
    ServerWorker *worker = malloc(sizeof(ServerWorker));
    if(worker == NULL){
        return NULL;
    }

    ServerWorkerConfig config_copy = {
        .cert_file_path = strdup(config.cert_file_path),
        .private_key_path = strdup(config.private_key_path),
        .port = config.port
    };

    if(config_copy.cert_file_path == NULL || config_copy.private_key_path == NULL){
        free((char *)config.cert_file_path);
        free((char *)config.private_key_path);
        goto exit_worker;
    }

    *worker = (ServerWorker){
        .ssl_ctx = NULL,
        .socket = -1,
        .epollfd = -1,
        .receivedCallback = {NULL, NULL},
        .connectCallback = {NULL, NULL},
        .disconnectCallback = {NULL, NULL},
        .config = config_copy
    };

    worker->stopfd = eventfd(0, 0);
    if(worker->stopfd == -1){
        goto exit_worker;
    }

    if(!_client_buffer_initialize(&worker->client_buffer)){
        goto exit_stop_fd;
    }

    if(!_client_queue_initialize(&worker->write_queue)){
        goto exit_client_buffer;
    }

    return worker;

exit_client_buffer:
    _client_buffer_clear(&worker->client_buffer);
exit_stop_fd:
    close(worker->stopfd);
exit_worker:
    free(worker);
    return NULL;
}

void server_worker_set_receive_callback(ServerWorker *worker, void (*callback)(void *u_data, void *u_client_data, const ClientHandle client, char *received, size_t size), void *u_data){
    worker->receivedCallback = (ReceivedCallback){
        .u_data = u_data,
        .invoke = callback
    };
}
void server_worker_set_connect_callback(ServerWorker *worker, void (*callback)(void *u_data, const ClientHandle client), void *u_data){
    worker->connectCallback = (ConnectCallback){
        .u_data = u_data,
        .invoke = callback
    };
}
void server_worker_set_disconnect_callback(ServerWorker *worker, void (*callback)(void *u_data, void * u_client_data, const ClientHandle client), void *u_data){
    worker->disconnectCallback = (DisconnectCallback){
        .u_data = u_data,
        .invoke = callback
    };
}
ServerWorkerStatus server_worker_attach_client_data(ServerWorker *worker, const ClientHandle handle, void *u_client_data){
    Client *client = _client_buffer_get_client(worker, handle);
    if(client == NULL){
        return ServerWorkerClientDisconnected;
    }
    client->u_client_data = u_client_data;
    _client_buffer_release_client(worker, handle);
    return ServerWorkerStatusOk;
}

void server_worker_set_ssl_ctx_cb(ServerWorker *worker, bool (*callback)(void *u_data, SSL_CTX *ctx ), void *u_data){
    worker->sslCtxCallback = (ConfigureSSLCtxCallback){
        .u_data = u_data,
        .invoke = callback
    };
}

void server_worker_free(ServerWorker *worker){
    if(worker == NULL){
        return;
    }

    LOG_DEBUG("Freeing ssl ctx");
    if(worker->ssl_ctx){
        SSL_CTX_free(worker->ssl_ctx);
        worker->ssl_ctx = NULL;
    }

    LOG_DEBUG("Freeing socket");
    if(worker->socket > 0){
        close(worker->socket);
        worker->socket = -1;
    }

    LOG_DEBUG("Freeing epoll");
    if(worker->epollfd > 0){
        close(worker->epollfd);
        worker->epollfd = -1;
    }

    LOG_DEBUG("Freeing stopdf");
    if(worker->stopfd > 0){
        close(worker->stopfd);
        worker->stopfd = -1;
    }

    LOG_DEBUG("Freeing client buffer");
    _client_buffer_clear(&worker->client_buffer);

    LOG_DEBUG("Freeing client queue");
    _client_queue_clear(&worker->write_queue);

    LOG_DEBUG("Cert/private key paths");
    free((char *)worker->config.cert_file_path);
    free((char *)worker->config.private_key_path);

    free(worker);
}

ServerWorkerStatus server_worker_run(ServerWorker *worker){
    assert(worker != NULL);
    assert(worker->ssl_ctx ==NULL);
    assert(worker->socket < 0);

    worker->ssl_ctx = _create_ssl_context(&worker->config);
    if(worker->ssl_ctx == NULL){
        return ServerWorkerUnableToCreateSSLContext;
    }
    if(worker->sslCtxCallback.invoke && 
            !worker->sslCtxCallback.invoke(worker->sslCtxCallback.u_data, worker->ssl_ctx)){
        return ServerWorkerUnableToCreateSSLContext;
    }

    worker->socket = _create_listen_socket(worker->config.port);

    if(worker->socket < 0){
        return ServerWorkerPortCreationError;
    }

    return _listen(worker);
}

ServerWorkerStatus server_worker_send(ServerWorker *worker, ClientHandle handle, const char *buffer, size_t buffer_size){
    assert(worker != NULL);
    assert(buffer != NULL);
    Client *client = _client_buffer_get_client(worker, handle);
    if(client == NULL){
        return ServerWorkerClientDisconnected;
    }

    pthread_mutex_lock(&client->write_lock);

    _data_buffer_add(&client->out_buffer, buffer, buffer_size);
    _client_queue_enqueue(&worker->write_queue, handle);

    pthread_mutex_unlock(&client->write_lock);

    _client_buffer_release_client(worker, handle);

    return ServerWorkerStatusOk;
}

void server_worker_request_stop(ServerWorker *worker){
    LOG_INFO("Request stop");
    assert(worker);
    assert(worker->stopfd > 0);
    uint64_t buff = 1;
    write(worker->stopfd, &buff, sizeof(buff));
}

static ServerWorkerStatus _listen(ServerWorker *worker){
    assert(worker != NULL);
    assert(worker->socket > 0);
    assert(worker->stopfd > 0);
    assert(worker->ssl_ctx != NULL);
    assert(worker->epollfd < 0);
    assert(worker->write_queue.clients != NULL);
    assert(worker->write_queue.queue_size >= WRITE_QUEUE_DEFAULT_SIZE);
    assert(worker->write_queue.enqueu_event_fd >= 0);
    assert(worker->client_buffer.clients != NULL);
    assert(worker->client_buffer.clients[0].generation == 0);

    ServerWorkerStatus status = ServerWorkerStatusOk;

    worker->epollfd = epoll_create1(0);
    if(worker->epollfd < 0){
        ERRNO_ERROR("Failed creating epoll");
        return ServerWorkerListenError;
    }

    struct epoll_event socket_cfg = {
        .events = EPOLLIN,
        .data.fd = worker->socket
    };
    if(epoll_ctl(worker->epollfd, EPOLL_CTL_ADD, worker->socket, &socket_cfg) < 0){
        ERRNO_ERROR("Failed to listen");
        status = ServerWorkerListenError;
        goto exit_epoll;
    }

    struct epoll_event stop_cfg = {
        .events = EPOLLIN,
        .data.fd = worker->stopfd
    };
    if(epoll_ctl(worker->epollfd, EPOLL_CTL_ADD, worker->stopfd, &stop_cfg) < 0){
        ERRNO_ERROR("Failed to listen on stop signal");
        status = ServerWorkerListenError;
        goto exit_socket;
    }

    struct epoll_event write_cfg = {
        .events = EPOLLIN,
        .data.fd = worker->write_queue.enqueu_event_fd
    };
    if(epoll_ctl(worker->epollfd, EPOLL_CTL_ADD, worker->write_queue.enqueu_event_fd, &write_cfg) < 0){
        ERRNO_ERROR("Failed to listen on write signal");
        status = ServerWorkerListenError;
        goto exit_stop_fd;
    }

    LOG_INFO("Listening on port %d...", worker->config.port);

    struct epoll_event events[16];
    while(true){
        int epoll_result = epoll_wait(worker->epollfd, events, sizeof(events)/sizeof(struct epoll_event), -1);
        if(epoll_result == -1){
            if(errno == EINTR){
                LOG_INFO("Program stop signal received");
            }
            else{
                ERRNO_ERROR("Wait failed");
                status = ServerWorkerListenError;
            }
            goto exit_clients;

        }else if(epoll_result == 0){
            ERROR("What?\n");
            continue;
        }

        for(size_t i = 0; i < epoll_result; i++){
            struct epoll_event event = events[i];
            if(event.data.fd == worker->stopfd){
                LOG_INFO("Stop signal received");
                uint64_t buff = 0;
                read(worker->stopfd, &buff, sizeof(buff));
                LOG_INFO("Stopping");
                goto exit_clients;
            }
            else if(event.data.fd == worker->write_queue.enqueu_event_fd){
                LOG_INFO("Write signal received");
                _handle_write_signal(worker);
                LOG_INFO("Write signal handled");
                continue;
            }
            else if(event.data.fd == worker->socket){
                LOG_INFO("Client connectiong");
                Client *client = _accept_client(worker);
                if(client == NULL){
                    continue; 
                }
                assert(client->socket > 0);
                struct epoll_event ev  = {
                    .events = EPOLLIN | EPOLLOUT | EPOLLET,
                    .data = client
                };
                if(epoll_ctl(worker->epollfd, EPOLL_CTL_ADD, client->socket, &ev) < 0){
                    ERRNO_ERROR("Failed to epoll client");
                    _disconnect_and_free_client(worker, client);
                    continue;
                }
                if(client->status == Idle){
                    _handle_client_read(worker, client);
                }
                continue;
            }
            else{
                Client *client = event.data.ptr;
                if(client->status == Handshake){
                    LOG_INFO("Handling data from client for handshake");
                    _handle_client_handshake(worker, client);
                    if(client->status == Idle){
                        _handle_client_read(worker, client);
                    }
                }
                else if(client->status & (Reading | Idle)){
                    LOG_INFO("Handling data from client");
                    _handle_client_read(worker, client);
                }
                else if(client->status & Writing){
                    LOG_INFO("Writing to client");
                    _handle_client_write(worker, client);
                }
                else{
                    ERROR("Unexpected event. Event of type %d received while in state %d", event.events, client->status);
                }
            }
        }
    }

exit_clients:
    _disconnect_all_clients(worker);
    epoll_ctl(worker->epollfd, EPOLL_CTL_DEL, worker->write_queue.enqueu_event_fd, NULL);
exit_stop_fd:
    epoll_ctl(worker->epollfd, EPOLL_CTL_DEL, worker->stopfd, NULL);
exit_socket:
    epoll_ctl(worker->epollfd, EPOLL_CTL_DEL, worker->socket, NULL);
exit_epoll:
    close(worker->epollfd);
    worker->epollfd = -1;
    return status;
}

static Client *_accept_client(ServerWorker *worker){
    assert(worker != NULL);
    assert(worker->socket > 0);
    assert(worker->ssl_ctx != NULL);

    LOG_INFO("Accepting client...");

    Client *client = malloc(sizeof(Client));
    if(client == NULL){
        return NULL;
    }
    *client = (Client){
        .has_been_connected = false,
        .ssl = NULL,
        .socket = -1,
        .u_client_data = NULL,
    };

    if(pthread_mutex_init(&client->write_lock, 0) != 0){
        goto exit_client;
    }

    LOG_DEBUG("Initialize data buffers");
    _data_buffer_initialize_empty(&client->in_flight_out_buffer);
    _data_buffer_initialize_empty(&client->out_buffer);
    socklen_t addrlen = sizeof(client->address);

    LOG_DEBUG("Accept client");
    client->socket = accept(worker->socket, (struct sockaddr *)&client->address, &addrlen);
    if(client->socket < 0){
        ERRNO_ERROR("Accept error");
        goto exit_write_lock;
    }


    if(!_set_nonblocking(client->socket)){
        ERRNO_ERROR("Unable to set client socket to nonblocking. Disconnecting client");
        goto exit_error_socket;
    }

    LOG_DEBUG("Create SSL");
    client->ssl = SSL_new(worker->ssl_ctx);
    if(client->ssl == NULL){
        goto exit_error_socket;
    }

    if(SSL_set_fd(client->ssl, client->socket) == 0){
        SSL_ERROR("Unable to set fd");
        goto exit_ssl;
    }

    if(!_client_buffer_add(&worker->client_buffer, client)){
        ERROR("Unable to store client in buffer. Disconnecting client");
        goto exit_ssl;
    }

    LOG_DEBUG("Perform SSL handshake");
    _client_set_status(worker, client, Handshake);
    int accept_status = SSL_accept(client->ssl);
    if(accept_status <= 0){
        int reason = SSL_get_error(client->ssl, accept_status);
        if(reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE){
            SSL_ERROR("Failed when accepting ssl client");
            goto exit_client_buffer;
        }
    }else{
        client->has_been_connected = true;
        if(worker->connectCallback.invoke){
            worker->connectCallback.invoke(worker->connectCallback.u_data, client->handle);
        }
        _client_set_status(worker, client, Idle);
    }

    LOG_DEBUG("Tried performing SSL handshake, but failed");

    char buff[128];
    _ip_str((struct sockaddr *)&client->address, buff, sizeof(buff));
    LOG_INFO("Client with ip %s connected", buff);

    return client;

exit_client_buffer:
    _client_buffer_remove(&worker->client_buffer, client);
exit_ssl:
    SSL_free(client->ssl);
    client->ssl = NULL;
exit_error_socket:
    close(client->socket);
    client->socket = -1;
exit_write_lock:
    pthread_mutex_destroy(&client->write_lock);
exit_client:
    free(client);
    return NULL;
}

static void _handle_write_signal(ServerWorker *worker){
    assert(worker != NULL);

    uint64_t buff;
    read(worker->write_queue.enqueu_event_fd, &buff, sizeof(buff));
    
    ClientHandle write_clients[32];
    size_t buffer_size = sizeof(write_clients)/sizeof(ClientHandle);
    size_t count = buffer_size;
    while(count == buffer_size){
        count = _client_queue_dequeue_n(&worker->write_queue, write_clients, sizeof(write_clients) / sizeof(ClientHandle));
        LOG_INFO("Writing to %zu clients", count);
        for(size_t i = 0; i < count; i++){
            ClientHandle handle = write_clients[i];
            Client *client = _client_buffer_get_client(worker, handle);
            if(client == NULL){
                LOG_INFO("Write buffer contains disconnected client, ignoring...");
            }
            else{
                if(client->status & Idle){
                    _handle_client_write(worker, client);
                }else{
                    LOG_DEBUG("Unable to write to client. Client in state %d. Will write later", client->status);
                }
                _client_buffer_release_client(worker, handle);
            }
        }
    }
}

static void _handle_client_write(ServerWorker *worker, Client *client){
    assert(worker != NULL);
    assert(client != NULL);
    assert(client->ssl != NULL);
    assert(client->status & (Idle | Writing));

    if(client->in_flight_out_buffer.used_size == 0){
        DataBuffer temp = client->in_flight_out_buffer;
        client->in_flight_out_buffer = client->out_buffer;
        client->out_buffer = temp;
    }

    if(client->in_flight_out_buffer.used_size == 0){
        return;
    }

    _client_set_status(worker, client, Writing);

    int status = SSL_write(client->ssl, client->in_flight_out_buffer.data, client->in_flight_out_buffer.used_size);
    if(status <= 0){
        int reason = SSL_get_error(client->ssl, status);
        if(reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE){
            SSL_ERROR("Failed when writing to ssl client. Disconnecting");
            _disconnect_and_free_client(worker, client);
            return;
        }
    }

    client->in_flight_out_buffer.used_size = 0;
    if(client->out_buffer.used_size > 0){
        LOG_DEBUG("Recursive handle client write");
        _handle_client_write(worker, client);
    }

    _client_set_status(worker, client, Idle);
}

static void _handle_client_handshake(ServerWorker *worker, Client *client){
    assert(worker != NULL);
    assert(client != NULL);
    assert(client->ssl != NULL);
    assert(client->status == Handshake);

    int accept_status = SSL_accept(client->ssl);
    if(accept_status > 0){
        char ipbuff[128];
        _ip_str((struct sockaddr *)&client->address, ipbuff, sizeof(ipbuff));
        LOG_INFO("Handshake done for %s", ipbuff);
        _client_set_status(worker, client, Idle);
        client->has_been_connected = true;
        if(worker->connectCallback.invoke != NULL){
            worker->connectCallback.invoke(worker->connectCallback.u_data, client->handle);
        }
        return;
    }

    int reason = SSL_get_error(client->ssl, accept_status);
    if(reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE){
        SSL_ERROR("Failed when accepting ssl client. Disconnecting");
        _disconnect_and_free_client(worker, client);
    }
}

static void _handle_client_read(ServerWorker *worker, Client *client){
    assert(worker != NULL);
    assert(client != NULL);
    assert(client->socket > 0);
    bool is_blocking;
    assert(_try_check_is_nonblocking(client->socket, &is_blocking) && is_blocking);
    assert(client->status & (Idle | Reading));

    while(1){
        char buff[1024];
        size_t n;
        int read_status = SSL_read_ex(client->ssl, buff, sizeof(buff), &n);
        if(read_status == 0){
            int reason = SSL_get_error(client->ssl, read_status);
            if(reason == SSL_ERROR_ZERO_RETURN){
                LOG_DEBUG("ZERO Return, will disconnect client");
                _client_set_status(worker, client, Idle);
                LOG_INFO("Flushing buffers with %zu and %zu bytes", client->in_flight_out_buffer.used_size, client->out_buffer.used_size);
                _handle_client_write(worker, client);
                _disconnect_and_free_client(worker, client);
                return;
            }
            else if(reason == SSL_ERROR_WANT_READ){
                LOG_DEBUG("Wait for more");
                _client_set_status(worker, client, Idle);
                return;
            }
            else if(reason == SSL_ERROR_WANT_WRITE){
                LOG_DEBUG("Wait for write");
                _client_set_status(worker, client, Reading);
                return;
            }
            else{
                SSL_ERROR("Failed when reading from ssl client (Reason %s). Disconnecting", ERR_reason_error_string(reason));
                _disconnect_and_free_client(worker, client);
                return;
            }
        }
        else if(read_status == 1){
            LOG_DEBUG("%zu bytes of data received", n);
            if(worker->receivedCallback.invoke != NULL){
                worker->receivedCallback.invoke(worker->receivedCallback.u_data, client->u_client_data, client->handle, buff, n);
            }
        }
        else{
            assert(false && "Unexpected status from read");
        }
    }
}

static void _disconnect_all_clients(ServerWorker *worker){
    assert(worker != NULL);
    assert(worker->client_buffer.clients != NULL || worker->client_buffer.client_buffer_size == 0);
    assert(worker->epollfd > 0);
    LOG_DEBUG("Disconnect all clients");

    ClientBuffer *buffer = &worker->client_buffer;
    for(size_t i = 0; i < buffer->client_buffer_size; i++){
        Client *client = buffer->clients[i].client;
        if(client == NULL){
            continue;
        }
        _disconnect_and_free_client(worker, client);
    }   
}

static void _disconnect_and_free_client(ServerWorker *worker, Client *client){
    assert(worker != NULL);
    assert(worker->epollfd > 0);
    assert(client != NULL);
    assert(client->socket > 0);
    assert(client->handle.index < worker->client_buffer.client_buffer_size);

    if(client->has_been_connected && worker->disconnectCallback.invoke){
        worker->disconnectCallback.invoke(worker->disconnectCallback.u_data, client->u_client_data, client->handle);
    }

    ClientEntry *entry = &worker->client_buffer.clients[client->handle.index];
    assert(entry->generation == client->handle.generation);

    entry->generation++;
    _client_set_status(worker, client, Stopped);

    pthread_mutex_t dummy;
    if(pthread_mutex_init(&dummy, 0) != 0){
        ERRNO_ERROR("Unable to create dummy lock. Try to disconnect client anyway");
    }
    else{
        pthread_mutex_lock(&dummy);
        LOG_DEBUG("Waiting for %d writers to exit", atomic_load(&entry->accessor_count));
        while(atomic_load(&entry->accessor_count) > 0){
            pthread_cond_wait(&entry->no_accessors, &dummy);
        }
        pthread_mutex_unlock(&dummy);
        pthread_mutex_destroy(&dummy);
    }

    char ipbuff[128];
    _ip_str((struct sockaddr *)&client->address, ipbuff, sizeof(ipbuff));
    LOG_INFO("Disconnecting client %s", ipbuff);

    if(epoll_ctl(worker->epollfd, EPOLL_CTL_DEL, client->socket, NULL) < 0){
        ERRNO_ERROR("Unable to remove client for polling");
    }       
    close(client->socket);
    client->socket = -1;
    _client_buffer_remove(&worker->client_buffer, client);

    _data_buffer_clear(&client->out_buffer);
    _data_buffer_clear(&client->in_flight_out_buffer);

    if(client->ssl != NULL){
        SSL_free(client->ssl);
        client->ssl = NULL;
    }

    client->handle = (ClientHandle){
        .index = -1,
        .generation = 0,
    };

    free(client);
    LOG_DEBUG("Client freed and disconnected");
}

static void _client_set_status(ServerWorker *worker, Client *client, ClientStatus status){
    assert(worker != NULL);
    assert(client != NULL);

    client->status = status;
    if(status == Idle){
        if(client->out_buffer.used_size > 0){
            _handle_client_write(worker, client);
        }
    }
}

static SSL_CTX * _create_ssl_context(ServerWorkerConfig *config){
    assert(config != NULL);
    assert(config->cert_file_path != NULL);
    assert(config->private_key_path != NULL);

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if(ctx == NULL){
        SSL_ERROR("Unable to create SSL_context");
        return NULL;
    }

    if(!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)){
        SSL_ERROR("Unable to set TLS version");
        return NULL;
    }

    LOG_INFO("Using files, cert: %s, private key: %s\n", config->cert_file_path, config->private_key_path);

    if(SSL_CTX_use_certificate_file(ctx, config->cert_file_path, SSL_FILETYPE_PEM) <= 0){
        SSL_ERROR("Unable to use certificate file");
        goto error;
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, config->private_key_path, SSL_FILETYPE_PEM) <= 0){
        SSL_ERROR("Unable to use private key file");
        goto error;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        SSL_ERROR("Private key does not match the certificate public key\n");
        goto error;
    }
    if(!SSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384")){

        SSL_ERROR("Unalbe to set cipher list ");
        goto error;
    }
    if (!SSL_CTX_set_ciphersuites(ctx,
                "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")){

        SSL_ERROR("Unable to set cipher suits");
        goto error;
    }
    if(!SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1)){
        SSL_ERROR("Unable to disable tls versions");
        goto error;
    }

    LOG_INFO("SSL Context created");
    
    return ctx;

error:
    SSL_CTX_free(ctx);
    return NULL;
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

    if(listen(sockfd, 3) < 0){
        ERRNO_ERROR("Listen");
        return -1;
    }

    return sockfd;
}

static int _ip_str(struct sockaddr *sockaddr, char *result, size_t buffer_size){
    if(sockaddr->sa_family == AF_INET){
        struct sockaddr_in *sockaddr_ipv4 = (struct sockaddr_in *)sockaddr;
        uint8_t *addr = (uint8_t *)&sockaddr_ipv4->sin_addr.s_addr;
        return snprintf(result, buffer_size, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
    }
    if(sockaddr->sa_family == AF_INET6){
        struct sockaddr_in6 *sockaddr_ipv6 = (struct sockaddr_in6 *)sockaddr;
        uint8_t *addr = (uint8_t *)&sockaddr_ipv6->sin6_addr;
        return snprintf(result, buffer_size, "%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X", 
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8],
                addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    }

    return snprintf(result, buffer_size, "Unknown type");
}

static bool _set_nonblocking(int socketfd){
    int flags = fcntl(socketfd, F_GETFL, 0);
    if (flags == -1){
        return false;
    }

    return fcntl(socketfd, F_SETFL, flags | O_NONBLOCK) != -1;
}

static bool _try_check_is_nonblocking(int socketfd, bool *result){
    int flags = fcntl(socketfd, F_GETFL, 0);
    if (flags == -1){
        return false;
    }

    *result = flags & O_NONBLOCK ? true : false;
    return true;
}

static bool _client_buffer_initialize(ClientBuffer *buffer){
    LOG_DEBUG("Initialilzing client buffer");
    *buffer = (ClientBuffer){
        .client_buffer_size = CLIENT_BUFFER_DEFAULT_SIZE,
        .clients = calloc(CLIENT_BUFFER_DEFAULT_SIZE, sizeof(ClientEntry))
    };

    LOG_DEBUG("First has %lu", buffer->clients[0].generation);
    return buffer->clients != NULL;
}

static void _client_buffer_clear(ClientBuffer *buffer){
    LOG_DEBUG("Clearing client buffer");
    if(buffer == NULL){
        return;
    }
    if(buffer->clients == NULL){
        return;
    }

    LOG_DEBUG("Destroying conds in client buffer");
    for(size_t i = 0; i < buffer->client_buffer_size; i++){
        if(buffer->clients[i].client != NULL){
            pthread_cond_destroy(&buffer->clients[i].no_accessors);
        }
    }

    LOG_DEBUG("Freeing client buffer");
    buffer->client_buffer_size = 0;
    free(buffer->clients);
    buffer->clients = NULL;

    LOG_DEBUG("Client buffer cleared");
}

static bool _client_buffer_add(ClientBuffer *buffer, Client *client){
    assert(buffer != NULL);
    assert(client != NULL);

    if(buffer->clients == NULL || buffer->client_buffer_size < CLIENT_BUFFER_DEFAULT_SIZE){
        LOG_DEBUG("Invalid client buffer size (%zX, %zu). Will resize", buffer->client_buffer_size, buffer->client_buffer_size);
        ClientEntry *new_buffer = calloc(CLIENT_BUFFER_DEFAULT_SIZE, sizeof(ClientEntry));
        if(new_buffer == NULL){
            return false;
        }
        memcpy(new_buffer, buffer->clients, buffer->client_buffer_size * sizeof(ClientEntry));
        free(buffer->clients);
        buffer->clients = new_buffer;
        buffer->client_buffer_size = CLIENT_BUFFER_DEFAULT_SIZE;
    }

    ssize_t free_index = -1;
    for(size_t i = 0; i < buffer->client_buffer_size; i++){
        if(buffer->clients[i].client == NULL){
            free_index = i;
            break;
        }
    }

    if(free_index == -1){
        LOG_DEBUG("Client buffer too small, resizing");
        size_t new_size = buffer->client_buffer_size * CLIENT_BUFFER_GROWTH_RATE;
        assert(new_size > buffer->client_buffer_size);
        ClientEntry *new_buffer = realloc(buffer->clients, new_size * sizeof(ClientEntry));
        if(new_buffer == NULL){
            return false;
        }
        free_index = buffer->client_buffer_size;
        buffer->clients = new_buffer;

        memset(new_buffer + buffer->client_buffer_size, 0, (new_size - buffer->client_buffer_size) * sizeof(ClientEntry));

        buffer->client_buffer_size = new_size;
    }

    LOG_DEBUG("Adding to client buffer at %d/%d", free_index, buffer->client_buffer_size);
    ClientEntry *entry = &buffer->clients[free_index];
    entry->client = client;
    client->handle = (ClientHandle){
        .generation = entry->generation,
        .index = free_index
    };
    LOG_DEBUG("Adding at gernation %lu", entry->generation);
    if(pthread_cond_init(&entry->no_accessors, 0) != 0){
        entry->client = NULL;
        ERRNO_ERROR("Unable to create \"no accessors\" condition");
        return false;
    }

    return true;
}

static void _client_buffer_remove(ClientBuffer *buffer, Client *client){
    assert(buffer != NULL);
    assert(buffer->clients != NULL);
    assert(client != NULL);
    assert(client->handle.index >= 0);
    assert(client->handle.index < buffer->client_buffer_size);

    ClientEntry *entry = &buffer->clients[client->handle.index];
//     assert(entry->generation == client->handle.generation);
    assert(atomic_load(&entry->accessor_count) == 0);

    entry->client = NULL;
    pthread_cond_destroy(&entry->no_accessors);
}

static Client *_client_buffer_get_client(ServerWorker *worker, ClientHandle handle){
    assert(worker != NULL);
    assert(worker->client_buffer.clients != NULL);
    assert(handle.index >= 0);

    if(handle.index >= worker->client_buffer.client_buffer_size){
        return NULL;
    }
    ClientEntry *entry = &worker->client_buffer.clients[handle.index];
    if(entry->generation != handle.generation){
        return NULL;
    }
    atomic_fetch_add(&entry->accessor_count, 1);
    if(entry->generation != handle.generation){
        atomic_fetch_sub(&entry->accessor_count, 1);
        return NULL;
    }

    return entry->client;
}

static void _client_buffer_release_client(ServerWorker *worker, ClientHandle handle){
    assert(worker != NULL);
    assert(worker->client_buffer.clients != NULL);
    assert(handle.index >= 0);
    assert(handle.index < worker->client_buffer.client_buffer_size);

    ClientEntry *entry = &worker->client_buffer.clients[handle.index];
    assert(entry->generation == handle.generation);

    int prev = atomic_fetch_sub(&entry->accessor_count, 1);
    if(prev == 1){
        pthread_cond_signal(&entry->no_accessors);
    }
}


static void _data_buffer_initialize_empty(DataBuffer *buffer){
    *buffer = (DataBuffer){
        .buffer_size = 0,
        .data = NULL,
        .used_size = 0
    };
}

static bool _data_buffer_initialize_with_data(DataBuffer *buffer, const char *data, size_t data_len){
    *buffer = (DataBuffer){
        .data = malloc(data_len),
        .used_size = data_len,
        .buffer_size = data_len,
    };
    if(buffer->data == NULL){
        return false;
    }

    memcpy(buffer->data, data, data_len);
    return true;
}

static void _data_buffer_clear(DataBuffer *buffer){
    if(buffer == NULL){
        return;
    }

    buffer->buffer_size = 0;
    buffer->used_size = 0;

    if(buffer->data != NULL){
        free(buffer->data);
        buffer->data = NULL;
    }
}

static bool _data_buffer_add(DataBuffer *buffer, const char *data, size_t data_len){
    assert(buffer != NULL);
    assert(data != NULL || data_len == 0);

    if(buffer->used_size == 0 || buffer->data == NULL){
        _data_buffer_clear(buffer);
        return _data_buffer_initialize_with_data(buffer, data, data_len);
    }

    size_t required_size = buffer->used_size + data_len;
    if(required_size > buffer->buffer_size){
        char *new_buffer = realloc(buffer->data, required_size);
        if(new_buffer == NULL){
            return false;
        }
        buffer->data = new_buffer;
        buffer->buffer_size = required_size;
    }

    memcpy(buffer->data + buffer->used_size, data, data_len);
    buffer->used_size += data_len;

    return true;
}

bool _client_queue_initialize(ClientQueue *queue){
    assert(queue != NULL);
    *queue = (ClientQueue){
        .clients = malloc(WRITE_QUEUE_DEFAULT_SIZE * sizeof(ClientHandle)),
        .queue_size = WRITE_QUEUE_DEFAULT_SIZE,
        .dequeue = 0,
        .enqueue = 0,
    };
    if(queue->clients == NULL){
        return false;
    }
    if(pthread_mutex_init(&queue->lock, NULL) != 0){
        free(queue->clients);
        return false;
    }
    queue->enqueu_event_fd = eventfd(0, 0);
    if(queue->enqueu_event_fd == -1){
        free(queue->clients);
        return false;
    }

    return true;
}

static void _client_queue_clear(ClientQueue *queue){
    if(queue == NULL){
        return;
    }
    if(queue->clients != NULL){
        free(queue->clients);
    }

    assert(queue->enqueu_event_fd >= 0);
    close(queue->enqueu_event_fd);

    pthread_mutex_destroy(&queue->lock);
    *queue = (ClientQueue){
        .clients = NULL,
        .queue_size = 0,
        .dequeue = 0,
        .enqueue = 0,
    };
}

static bool _client_queue_enqueue(ClientQueue *queue, ClientHandle client){
    assert(queue != NULL);
    assert(queue->enqueu_event_fd >= 0);

    pthread_mutex_lock(&queue->lock);

    if(queue->clients == NULL || queue->queue_size < WRITE_QUEUE_DEFAULT_SIZE){
        if(!_client_queue_resize_without_lock(queue, CLIENT_BUFFER_DEFAULT_SIZE)){
            goto exit_failure;
        }
    }

    if((queue->enqueue + 1) % queue->queue_size== queue->dequeue){
        size_t new_size = queue->queue_size * WRITE_QUEUE_GROWTH_RATE;
        assert(new_size > queue->queue_size);
        if(!_client_queue_resize_without_lock(queue, new_size)){
            goto exit_failure;
        }
    }

    queue->clients[queue->enqueue] = client;
    queue->enqueue = (queue->enqueue + 1) % queue->queue_size;

exit_success:
    pthread_mutex_unlock(&queue->lock);
    uint64_t buff = 1;
    write(queue->enqueu_event_fd, &buff, sizeof(buff));
    return true;

exit_failure:
    pthread_mutex_unlock(&queue->lock);
    return false;
}

static bool _client_queue_resize_without_lock(ClientQueue *queue, size_t size){
    assert(queue != NULL);
    assert(size >= WRITE_QUEUE_DEFAULT_SIZE);

    if(queue->clients == NULL || queue->queue_size == 0){
        assert(queue->dequeue == 0);
        assert(queue->enqueue == 0);
        ClientHandle *clients = realloc(queue->clients, size * sizeof(ClientHandle));
        if(clients == NULL){
            return false;
        }
        queue->clients = clients;
        queue->queue_size = size;
        return true;
    }

    ClientHandle *new_buff = malloc(size * sizeof(ClientHandle));
    if(new_buff == NULL){
        return false;
    }
    size_t client_count = 0;
    if(queue->dequeue <= queue->enqueue){
        client_count = queue->enqueue - queue->dequeue;
        memcpy(new_buff, queue->clients + queue->dequeue, client_count * sizeof(ClientHandle));
    }
    else{
        size_t after_wrap_count = queue->enqueue;
        size_t before_wrap_count = queue->queue_size - queue->dequeue;
        client_count = after_wrap_count + before_wrap_count;
        memcpy(new_buff, queue->clients + queue->dequeue, before_wrap_count * sizeof(ClientHandle));
        memcpy(new_buff + before_wrap_count, queue->clients, after_wrap_count * sizeof(ClientHandle));
    }

    queue->dequeue = 0;
    queue->enqueue = client_count;
    queue->queue_size = size;
    free(queue->clients);
    queue->clients = new_buff;
    return true;
}

static bool _client_queue_dequeue(ClientQueue *queue, ClientHandle *result){
    assert(queue != NULL);
    assert(result != NULL);
    assert(queue->clients != NULL);

    pthread_mutex_lock(&queue->lock);

    if(queue->enqueue == queue->dequeue){
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    
    *result = queue->clients[queue->dequeue];
    queue->dequeue = (queue->dequeue + 1) % queue->queue_size;
    pthread_mutex_unlock(&queue->lock);

    return true;
}

static size_t _client_queue_dequeue_n(ClientQueue *queue, ClientHandle *result, size_t buffer_size){
    assert(queue != NULL);
    assert(result != NULL);

    if(queue->dequeue == queue->enqueue){
        return 0;
    }
    assert(queue->clients != NULL);

    pthread_mutex_lock(&queue->lock);

    if(queue->dequeue < queue->enqueue){
        size_t count = min(queue->enqueue - queue->dequeue, buffer_size);
        memcpy(result, queue->clients + queue->dequeue, count * sizeof(ClientHandle));
        queue->dequeue = (queue->dequeue + count) % queue->queue_size;
        pthread_mutex_unlock(&queue->lock);
        return count;
    }
    else{
        size_t after_wrap_count = queue->enqueue;
        size_t before_wrap_count = queue->queue_size - queue->dequeue;

        size_t count = min(before_wrap_count, buffer_size);
        memcpy(result, queue->clients + queue->dequeue, min(before_wrap_count, buffer_size) * sizeof(ClientHandle));

        if(buffer_size > before_wrap_count){
            memcpy(result + before_wrap_count, queue->clients, min(after_wrap_count, buffer_size - before_wrap_count) * sizeof(ClientHandle));
            count += min(after_wrap_count, buffer_size - before_wrap_count);
        }
        queue->dequeue = (queue->dequeue + count) % queue->queue_size;
        pthread_mutex_unlock(&queue->lock);

        return count;
    }
}
