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
#include "tls_server.h"
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

TlsServer *server;
typedef enum{
    Http2

}ClientType;

typedef struct{
    ClientType type;
    TlsServerClient client;
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
    tls_server_send(server, client_data->client, data, size);

    return true;
}

void on_disconnect(void *u_data, void *u_client_data){
    LOG_DEBUG("Handle disconnect work");
    Client *client_data = (Client *)u_client_data;
    cancellation_token_factory_cancel_and_free(client_data->token_factory);
    http2_client_free(client_data->http2Client);
    free(client_data);
    LOG_INFO("Client disconnected");
}

void on_connect(void *u_data, const TlsServerClient client){
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

    tls_server_attach_client_data(server, client, client_data);

    LOG_INFO("Client connected");
}

typedef struct{
    bool canceled;
    bool owned_by_io_uring;
    Client *client;
    pthread_mutex_t lock;
    Task task;
    CancellationTokenCallbackHandle cch;
}Work;

void _on_io_uring_done_work(void *args){
    Work *work = (Work *)args;
    LOG_DEBUG("Uring done");

    UringTask uring_task = work->task.uring_task;
    uring_task.callback(uring_task.ctx);

    cancellation_token_remove_callback(work->client->token, work->cch);
    pthread_mutex_destroy(&work->lock);
    free(work);
    LOG_INFO("Uring event handled\n");
}

void on_iouring_done(void *args){
    Work *work = (Work *)args;

    pthread_mutex_lock(&work->lock);
    if(!work->canceled){
        LOG_TRACE("Handling io_uring result");
        work->owned_by_io_uring = false;
        pthread_mutex_unlock(&work->lock);

        tls_server_enqueue_client_work(server, work->client->client, _on_io_uring_done_work, work);
    }
    else{
        pthread_mutex_unlock(&work->lock);
        LOG_DEBUG("Ignoring iouring completion, task canceled");
        UringTask uring_task = work->task.uring_task;
        IoUringOp op = uring_task.op;
        free(op.buff);
        close(op.fd);
        pthread_mutex_destroy(&work->lock);
        free(work);
    }

}

void _free_work_from_uring(void *args){
    Work *work = (Work *)args;
    pthread_mutex_lock(&work->lock);
    work->canceled = true;
    pthread_mutex_unlock(&work->lock);
    if(!work->owned_by_io_uring){
        pthread_mutex_destroy(&work->lock);
        free(work);
    }
}

typedef struct{
    Client *client;
    char *buffer;
    size_t data_size;
}OnDataCtx;

void on_data(void *u, void *u_client_data, uint8_t *buff, size_t len){
    LOG_DEBUG("Handle client data work %X\n", u_client_data);
    Client *client = (Client *)u_client_data;

    TaskList tasks = http2_client_handle_message_async(client->http2Client, (char *)buff, len, client->token);
    Task task;
    while(task_list_try_dequeue(&tasks, &task)){
        Work *work = malloc(sizeof(Work));
        work->client = client;
        work->task = task;
        work->canceled = false;
        work->owned_by_io_uring = true;
        assert(pthread_mutex_init(&work->lock, 0) == 0);
        IoUringCallback cb = {
            .invoke = on_iouring_done,
            .u_data = work
        };
        if(task.type == TaskTypeUring){
            io_uring_submit(uring, task.uring_task.op, cb);
        }
        CancellationTokenCallback ccb = {
            .on_cancel = _free_work_from_uring,
            .u_data = work,
        };
        cancellation_token_add_callback(client->token, ccb, &work->cch);
    }

    task_list_clear(&tasks);
    LOG_INFO("Finished handling client data work %X\n", u_client_data);
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

    TlsServerConfiguration config = tls_server_default_configuration(6969, cert_path, private_key_path);
    config.thread_count = 2;
    config.receive_callback.invoke = on_data;
    config.connect_callback.invoke = on_connect;
    config.disconnect_callback.invoke = on_disconnect;
    config.ssl_ctx_callback.invoke = configure_ssl;


    server = tls_server_new(config);
    assert(server != NULL);

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    signal(SIGPIPE, error_handler);

    tls_server_run(server);

    tls_server_free(server);
    http_core_free();

exit_manager:
    config_manager_free(manager);
    return status;
}
