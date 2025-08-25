#include "server/server.h"
#include <fcntl.h>
#include <linux/io_uring.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include "http_core/http_core.h"
#include "openssl/ssl.h"
#include "assert.h"
#include "server_worker.h"
#include "config_manager.h"
#include "http2/http2.h"
#include "io_uring/io_uring.h"

#define LOG_CONTEXT "Server"
#include "logging.h"

#define TEST_NR 1

#if TEST_NR == 0
#include "thread_pool_perf_test.c"
#elif TEST_NR == 1
#include "thread_pool_test.c"
#else
#include "queue_test.c"
#endif

ServerWorker *sworker;
ThreadPool *thread_pool;
typedef enum{
    Http2

}ClientType;

typedef struct{
    ClientType type;
    ClientHandle client;
    ThreadPoolQueue queue;
    CancellationTokenFactory *token_factory;
    CancellationToken *token;
    union{
        Http2Client *http2Client;
    };
}Client;

static IoUring *uring;

void signal_handler(int signal){}

bool send_cb(void *u_data, const uint8_t *data, size_t size){
    Client *client_data = (Client *)u_data;
    server_worker_send(sworker, client_data->client, (char *)data, size);

    return true;
}

void _on_disconnect_work(void *data){
    LOG_DEBUG("Handle disconnect work");
    Client *client_data = (Client *)data;
    cancellation_token_factory_cancel_and_free(client_data->token_factory);
    http2_client_free(client_data->http2Client);
    threadpool_release_queue(thread_pool, client_data->queue);
    free(client_data);
    LOG_INFO("Client disconnected");
}
void on_disconnect(void *u_data, void *u_client_data, const ClientHandle client){
    Client *client_data = (Client *)u_client_data;
    threadpool_enqueue_work(thread_pool, client_data->queue, _on_disconnect_work, client_data);
    LOG_DEBUG("Client disconnect work enqued");
}

void on_connect(void *u_data, const ClientHandle client){
    Client *client_data = malloc(sizeof(Client));
    assert(client_data != NULL);
    Http2Client *http2Client = http2_client_new((Http2SendCb){.send = send_cb, .u_data = client_data});
    assert(http2Client != NULL);

    CancellationTokenFactory *factory = cancellation_token_factory_new();
    assert(factory != NULL);
    CancellationToken *token = cancellation_token_factory_create_token(factory);
    assert(token != NULL);

    *client_data = (Client){
        .type = Http2,
        .client = client,
        .token_factory = factory,
        .token = token,
        .http2Client = http2Client
    };

    assert(threadpool_try_create_new_queue(thread_pool, &client_data->queue));

    server_worker_attach_client_data(sworker, client, client_data);

    LOG_INFO("Client connected");
}

typedef struct{
    Client *client;
    Task task;
}Work;

void _on_io_uring_done_work(void *args){
    LOG_DEBUG("Uring done");
    Work *work = (Work *)args;
    UringTask uring_task = work->task.uring_task;
    uring_task.callback(uring_task.ctx);
    free(args);
    LOG_INFO("Uring event handled\n");
}

void on_iouring_done(void *args){
    Work *work = (Work *)args;
    threadpool_enqueue_work(thread_pool, work->client->queue, _on_io_uring_done_work, work);
}

typedef struct{
    Client *client;
    char *buffer;
    size_t data_size;
}OnDataCtx;

void _on_data_work(void *arg){
    LOG_DEBUG("Handle client data work %X\n", arg);
    OnDataCtx *ctx = (OnDataCtx *)arg;

    TaskList tasks = http2_client_handle_message_async(ctx->client->http2Client, ctx->buffer, ctx->data_size, ctx->client->token);
    Task task;
    while(task_list_try_dequeue(&tasks, &task)){
        Work *work = malloc(sizeof(Work));
        work->client = ctx->client;
        work->task = task;
        IoUringCallback cb = {
            .invoke = on_iouring_done,
            .u_data = work
        };
        if(task.type == TaskTypeUring){
            io_uring_submit(uring, task.uring_task.op, cb);
        }
    }

    free(ctx->buffer);
    free(ctx);
    task_list_clear(&tasks);
    LOG_INFO("Finished handling client data work %X\n", arg);
}

void on_data(void *u, void *u_client_data, const ClientHandle client, char *buff, size_t len){
    Client *client_data = (Client *)u_client_data;
    OnDataCtx *ctx = malloc(sizeof(OnDataCtx));
    assert(ctx != NULL);
    *ctx = (OnDataCtx){
        .buffer = malloc(len),
        .data_size = len,
        .client = client_data
    };
    assert(ctx->buffer != NULL);
    memcpy(ctx->buffer, buff, len);
    threadpool_enqueue_work(thread_pool, client_data->queue, _on_data_work, ctx);
    LOG_DEBUG("Enqueued client data work %X\n", ctx);
}

void error_handler(int signal){
    LOG_WARNING("Signal %d received. Ignoring...\n", signal);
}

int alpn_select_cb(SSL *ssl,
                   const unsigned char **out,
                   unsigned char *outlen,
                   const unsigned char *in,
                   unsigned int inlen,
                   void *arg) {

    static const unsigned char alpn_h2[] = { 
        2, 'h', '2',
        8, 'h','t','t','p','/','1', '.', '1'
    };

    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn_h2, sizeof(alpn_h2), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

bool configure_ssl(void *data, SSL_CTX *ctx){
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    return true;
}

int server_run(){
// #if TEST_NR == 0
//     return perf_test();
// #elif TEST_NR == 1
//     return chaotic_test();
// #elif TEST_NR == 2
//     return queue_test();
// #endif

    uring = io_uring_new();
    if(uring == NULL){
        assert(false && "Unable to allocate uring");
        return 1;
    }

    thread_pool = threadpool_new();
    if(thread_pool == NULL){
        assert(false && "Unable to allocate threadpool");
        return 1;
    }

    int status = 0;
    ConfigManager *manager = config_manager_load_from_appconfig();
    if(manager == NULL){
        fprintf(stderr, "Config Error: to load config file. Exiting...\n");
        return 1;
    }

    int port;
    const char *cert_path, *private_key_path, *cp;

    bool cert_status = config_manager_try_get_str(manager, "Certificate", &cert_path);
    bool key_status = config_manager_try_get_str(manager, "PrivateKey", &private_key_path);
    bool port_status = config_manager_try_get_int(manager, "Port", &port);
    bool content_path_status = config_manager_try_get_str(manager, "Content", &cp);

    if(!cert_status){
        fprintf(stderr, "Config Error: Unable to load 'Certificate'.\n");
    }
    if(!key_status){
        fprintf(stderr, "Config Error: Unable to load 'PrivateKey'.\n");
    }
    if(!port_status){
        fprintf(stderr, "Config Error: Unable to load 'Port'.\n");
    }
    if(!content_path_status){
        fprintf(stderr, "Config Error: Unable to load 'Content'.\n");
    }
    if(!cert_status || !key_status || !port_status || !content_path_status){
        fprintf(stderr, "Exiting...\n");
        status = 1;
        goto exit_manager;
    }

    if(!http_core_init(cp)){
        fprintf(stderr, "Unable to initialize http core\n");
        status = 1;
        goto exit_manager;
    }

    ServerWorkerConfig config = {
        .cert_file_path = cert_path,
        .private_key_path = private_key_path,
        .port = port
    };

    sworker = server_worker_new(config);
    assert(sworker != NULL);
    server_worker_set_receive_callback(sworker, on_data, NULL);
    server_worker_set_connect_callback(sworker, on_connect, NULL);
    server_worker_set_disconnect_callback(sworker, on_disconnect, NULL);
    server_worker_set_ssl_ctx_cb(sworker, configure_ssl, NULL);

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    signal(SIGPIPE, error_handler);

    server_worker_run(sworker);

    server_worker_free(sworker);
    threadpool_free(thread_pool);

exit_manager:
    config_manager_free(manager);
    return status;
}
