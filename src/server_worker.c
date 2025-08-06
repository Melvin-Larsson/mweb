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

#define CLIENT_BUFFER_DEFAULT_SIZE 16
#define CLIENT_BUFFER_GROWTH_RATE 1.5

typedef enum{
    HandShake = 1,
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

struct Client{
    bool valid;
    ClientStatus status;
    int socket;
    struct sockaddr_storage address;


    SSL *ssl;
    
    DataBuffer in_flight_out_buffer;
    DataBuffer out_buffer;
};

typedef struct{
    Client *clients;
    size_t client_buffer_size;
    size_t client_count;
}ClientBuffer;

typedef struct{
    Client **clients;
    size_t queue_size;
    size_t enqueu;
    size_t dequeu;
}ClientQueue;

typedef struct{
    void *u_data;
    void (*invoke)(void *u_data, const Client *client, char *received, size_t size);
}ReceivedCallback;

struct ServerWorker{
    int port;
    SSL_CTX *ssl_ctx;
    int socket;
    int stopfd;
    int epollfd;
    int write_event_fd;

    ClientBuffer client_buffer;
    ReceivedCallback receivedCallback;
};

static bool client_buffer_initialize(ClientBuffer *buffer);
static void client_buffer_cleanup(ClientBuffer *buffer);
static Client *client_buffer_add(ClientBuffer *buffer, Client client);
static void client_buffer_remove(ClientBuffer *buffer, Client *client);
static void client_buffer_defragment(ClientBuffer *buffer);

static void _data_buffer_initialize_empty(DataBuffer *buffer);
static bool _data_buffer_initialize_with_data(DataBuffer *buffer, const char *data, size_t data_len);
static void _data_buffer_clear(DataBuffer *buffer);
static bool _data_buffer_add(DataBuffer *buffer, const char *data, size_t data_len);

static SSL_CTX * _create_ssl_context();
static int _create_listen_socket(int port);
static ServerWorkerStatus _listen(ServerWorker *worker);


static Client * _accept_client(ServerWorker *worker);
static void _handle_client_write(ServerWorker *worker, Client *client);
static void _handle_client_read(ServerWorker *worker, Client *client);
static void _handle_client_handshake(ServerWorker *worker, Client *client);
static void _disconnect_all_clients(ServerWorker *worker);
static void _disconnect_and_free_client(ServerWorker *worker, Client *client);

static int _ip_str(struct sockaddr *sockaddr, char *result, size_t buffer_size);
static bool _set_nonblocking(int fd);
static bool _try_check_is_nonblocking(int fd, bool *result);

ServerWorker *server_worker_new(){
    ServerWorker *worker = malloc(sizeof(ServerWorker));
    if(worker == NULL){
        return NULL;
    }

    if(!client_buffer_initialize(&worker->client_buffer)){
        free(worker);
        return false;
    }

    *worker = (ServerWorker){
        .port = 6969,
        .stopfd = eventfd(0, 0),
        .ssl_ctx = NULL,
        .socket = -1,
        .epollfd = -1,
    };


    if(worker->stopfd == -1){
        free(worker);
        return NULL;
    }

    return worker;
}

void server_worker_set_receive_callback(ServerWorker *worker, void (*callback)(void *u_data, const Client *client, char *received, size_t size), void *u_data){
    worker->receivedCallback = (ReceivedCallback){
        .u_data = u_data,
        .invoke = callback
    };
}

void server_worker_free(ServerWorker *worker){
    if(worker == NULL){
        return;
    }

    if(worker->ssl_ctx){
        SSL_CTX_free(worker->ssl_ctx);
        worker->ssl_ctx = NULL;
    }

    if(worker->port > 0){
        close(worker->port);
    }

}

ServerWorkerStatus server_worker_run(ServerWorker *worker){
    ServerWorkerStatus status = ServerWorkerStatusOk;

    worker->ssl_ctx = _create_ssl_context();
    if(worker->ssl_ctx == NULL){
        status = ServerWorkerUnableToCreateSSLContext;
        goto cleanup;
    }

    worker->socket = _create_listen_socket(worker->port);

    if(worker->socket < 0){
        status = ServerWorkerPortCreationError;
        goto cleanup;
    }

    status = _listen(worker);


cleanup:
    server_worker_free(worker);
    return status;
}

//FIXME: Not thread safe, must be called from callback
ServerWorkerStatus server_worker_send(ServerWorker *worker, Client *client, char *buffer, size_t buffer_size){
    _data_buffer_add(&client->out_buffer, buffer, buffer_size);
    ClientStatus temp = client->status;
    client->status = Idle;
    _handle_client_write(worker, client);
    client->status = temp;
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
        return ServerWorkerListenError;
    }

    struct epoll_event stop_cfg = {
        .events = EPOLLIN,
        .data.fd = worker->stopfd
    };
    if(epoll_ctl(worker->epollfd, EPOLL_CTL_ADD, worker->stopfd, &stop_cfg) < 0){
        ERRNO_ERROR("Failed to listen on stop signal");
        return ServerWorkerListenError;
    }

    LOG_INFO("Listening on port %d...", worker->port);

    struct epoll_event events[16];
    while(true){
        int epoll_result = epoll_wait(worker->epollfd, events, sizeof(events)/sizeof(struct epoll_event), -1);
        if(epoll_result == -1){
            if(errno == EINTR){
                LOG_INFO("Program stop signal received");
                goto exit_ok;
            }
            ERRNO_ERROR("Wait failed");
            return ServerWorkerListenError;
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
                goto exit_ok;
            }
            if(event.data.fd == worker->socket){
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
                }
                if(client->status == Idle){
                    _handle_client_read(worker, client);
                }
                continue;
            }
            Client *client = event.data.ptr;
            if(client->status == HandShake){
                LOG_INFO("Handling data from client for handshake");
                _handle_client_handshake(worker, client);
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

exit_ok:
    LOG_INFO("Stopping server worker");
    _disconnect_all_clients(worker);
    close(worker->epollfd);
    worker->epollfd = -1;
    return ServerWorkerStatusOk;
}

static Client *_accept_client(ServerWorker *worker){
    assert(worker != NULL);
    assert(worker->socket > 0);
    assert(worker->ssl_ctx != NULL);

    LOG_INFO("Accepting client...");

    Client client = (Client){
        .ssl = NULL,
        .socket = -1,
    };

    _data_buffer_initialize_empty(&client.in_flight_out_buffer);
    _data_buffer_initialize_empty(&client.out_buffer);
    socklen_t addrlen = sizeof(client.address);
    client.socket = accept(worker->socket, (struct sockaddr *)&client.address, &addrlen);
    if(client.socket < 0){
        ERRNO_ERROR("Accept error");
        return NULL;
    }


    if(!_set_nonblocking(client.socket)){
        ERRNO_ERROR("Unable to set client socket to nonblocking. Disconnecting client");
        goto exit_error_socket;
    }

    client.ssl = SSL_new(worker->ssl_ctx);
    if(client.ssl == NULL){
        goto exit_error_socket;
    }
    if(SSL_set_fd(client.ssl, client.socket) == 0){
        SSL_ERROR("Unable to set fd");
        goto exit_ssl;
    }

    client.status = HandShake;
    int accept_status = SSL_accept(client.ssl);
    if(accept_status <= 0){
        int reason = SSL_get_error(client.ssl, accept_status);
        if(reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE){
            SSL_ERROR("Failed when accepting ssl client");
            goto exit_ssl;
        }
    }else{
       client.status = Idle; 
    }

    Client *result = client_buffer_add(&worker->client_buffer, client);
    if(result == NULL){
        ERROR("Unable to store client in buffer. Disconnecting client");
        goto exit_ssl;
    }

    char buff[128];
    _ip_str((struct sockaddr *)&client.address, buff, sizeof(buff));
    LOG_INFO("Client with ip %s connected", buff);

    return result;

exit_ssl:
    SSL_free(client.ssl);
exit_error_socket:
    close(client.socket);
    return NULL;
}

static void _handle_client_write(ServerWorker *worker, Client *client){
    assert(worker != NULL);
    assert(client != NULL);
    assert(client->ssl != NULL);
    assert(client->status & (Idle | Writing));

    client->status = Writing;

    if(client->in_flight_out_buffer.used_size == 0){
        DataBuffer temp = client->in_flight_out_buffer;
        client->in_flight_out_buffer = client->out_buffer;
        client->out_buffer = temp;

        client->out_buffer.used_size = 0;
    }

    int status = SSL_write(client->ssl, client->in_flight_out_buffer.data, client->in_flight_out_buffer.used_size);
    if(status <= 0){
        int reason = SSL_get_error(client->ssl, status);
        if(reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE){
            SSL_ERROR("Failed when accepting ssl client. Disconnecting");
            _disconnect_and_free_client(worker, client);
            return;
        }
    }

    client->in_flight_out_buffer.used_size = 0;
    if(client->out_buffer.used_size > 0){
        LOG_DEBUG("Recursive handle client write");
        _handle_client_write(worker, client);
    }
    client->status = Idle;
}

static void _handle_client_handshake(ServerWorker *worker, Client *client){
    assert(worker != NULL);
    assert(client != NULL);
    assert(client->ssl != NULL);
    assert(client->status == HandShake);

    int accept_status = SSL_accept(client->ssl);
    if(accept_status > 0){
        char ipbuff[128];
        LOG_INFO("HandShake done for %s", ipbuff);
        client->status = Idle;
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
        if(read_status <= 0){
            int reason = SSL_get_error(client->ssl, read_status);
            if(reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE){
                SSL_ERROR("Failed when reading from ssl client. Disconnecting");
                _disconnect_and_free_client(worker, client);
                return;
            }
            else{
                client->status = Reading;
                return;
            }
        }
        if(n == -1){
            if(errno == EAGAIN || errno == EWOULDBLOCK){
                client->status = Idle;
                return;
            }
            char ipbuff[128];
            _ip_str((struct sockaddr *)&client->address, ipbuff, sizeof(ipbuff));
            ERRNO_ERROR("Failed to read from client %s. Disconnecting", ipbuff);
            _disconnect_and_free_client(worker, client);
            return;
        }
        if(n == 0){
            _disconnect_and_free_client(worker, client);

            char ipbuff[128];
            _ip_str((struct sockaddr *)&client->address, ipbuff, sizeof(ipbuff));
            LOG_INFO("Client %s disconnected", ipbuff);
            return;
        }
        LOG_DEBUG("%zu bytes of data received", n);
        if(worker->receivedCallback.invoke != NULL){
            worker->receivedCallback.invoke(worker->receivedCallback.u_data, client, buff, n);
        }
    }
}

static void _disconnect_all_clients(ServerWorker *worker){
    assert(worker != NULL);
    assert(worker->client_buffer.clients != NULL || worker->client_buffer.client_count == 0);
    assert(worker->epollfd > 0);

    ClientBuffer *buffer = &worker->client_buffer;
    for(size_t i = 0; i < buffer->client_count; i++){
        Client *client = &buffer->clients[i];
        if(!client->valid){
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
    assert(client->valid);

    char ipbuff[128];
    _ip_str((struct sockaddr *)&client->address, ipbuff, sizeof(ipbuff));
    LOG_INFO("Disconnecting client %s", ipbuff);

    if(epoll_ctl(worker->epollfd, EPOLL_CTL_DEL, client->socket, NULL) < 0){
        ERRNO_ERROR("Unable to remove client for polling");
    }       
    close(client->socket);
    client->socket = -1;
    client->status = Stopped; 
    client_buffer_remove(&worker->client_buffer, client);

    _data_buffer_clear(&client->out_buffer);
    _data_buffer_clear(&client->in_flight_out_buffer);

    if(client->ssl){
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
}

static SSL_CTX * _create_ssl_context(){
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

    char *cert_file = getenv("CERT_FILE_PATH");
    char *private_key_file = getenv("PRIVATE_KEY_FILE_PATH");

    if(cert_file == NULL){
        ERROR("CERT_FILE_PATH environment variable is not set");
        goto error;
    }
    if(private_key_file == NULL){
        ERROR("PRIVATE_KEY_FILE_PATH environment variable is not set");
        goto error;
    }

    LOG_INFO("Using files, cert: %s, private key: %s\n", cert_file, private_key_file);

    if(SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0){
        SSL_ERROR("Unable to use certificate file");
        goto error;
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM) <= 0){
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

static bool client_buffer_initialize(ClientBuffer *buffer){
    *buffer = (ClientBuffer){
        .client_buffer_size = 0,
        .client_count = CLIENT_BUFFER_DEFAULT_SIZE,
        .clients = malloc(sizeof(Client) * CLIENT_BUFFER_DEFAULT_SIZE)
    };

    return buffer->clients != NULL;
}

static void client_buffer_cleanup(ClientBuffer *buffer){
    if(buffer == NULL){
        return;
    }

    free(buffer->clients);
}

static Client *client_buffer_add(ClientBuffer *buffer, Client client){
    assert(buffer != NULL);

    if(buffer->clients == NULL || buffer->client_buffer_size < CLIENT_BUFFER_DEFAULT_SIZE){
        Client *new_buffer = realloc(buffer->clients, CLIENT_BUFFER_DEFAULT_SIZE * sizeof(Client));
        if(new_buffer == NULL){
            return NULL;
        }
        buffer->clients = new_buffer;
        buffer->client_buffer_size = CLIENT_BUFFER_DEFAULT_SIZE;
    }

    if(buffer->client_count == buffer->client_buffer_size){
        client_buffer_defragment(buffer);
        if(buffer->client_count == buffer->client_buffer_size){
            size_t new_size = buffer->client_count * CLIENT_BUFFER_GROWTH_RATE;
            Client *new_buffer = realloc(buffer->clients, new_size * sizeof(Client));
            if(new_buffer == NULL){
                return NULL;
            }
            buffer->clients = new_buffer;
            buffer->client_buffer_size = new_size;
        }
    }
    Client *result = &buffer->clients[buffer->client_count];
    *result = client;
    result->valid = true;
    buffer->client_count++;

    return result;
}

static void client_buffer_defragment(ClientBuffer *buffer){
    assert(buffer != NULL);

    size_t free_index = 0;
    for(size_t i = 0; i < buffer->client_count; i++){
        if(buffer->clients[i].valid){
            buffer->clients[free_index++] = buffer->clients[i];
        }
    }
    for(size_t i = free_index; i < buffer->client_count; i++){
        buffer->clients[i].valid = false;
    }
    buffer->client_count = free_index;
}

static void client_buffer_remove(ClientBuffer *buffer, Client *client){
    client->valid = false;
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

    memcpy(buffer->data, data, data_len);
    return buffer->data != NULL;
}

static void _data_buffer_clear(DataBuffer *buffer){
    if(buffer == NULL){
        return;
    }

    buffer->buffer_size = 0;
    buffer->used_size = 0;
    free(buffer->data);
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
